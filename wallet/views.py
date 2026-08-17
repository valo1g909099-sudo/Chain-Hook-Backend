from decimal import Decimal
import random
import json
import urllib.request
import urllib.error
from django.utils import timezone
from django.core import signing
from django.core.signing import BadSignature, SignatureExpired
from django.db.models import Sum
from datetime import timedelta
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated

from .models import Wallet, Transaction, CurrencyPriceHistory, UserCurrency
from .serializers import WalletSerializer, TransactionSerializer, CurrencyPriceHistorySerializer

# Must match the users app's Client model
from users.models import Client  # adjust import path to your actual app label

MONTHLY_CAP = Decimal('10000000.00')
SUPPORTED_CURRENCIES = {'USD', 'EUR', 'JPY', 'GBP'}

# Must be IDENTICAL to CLIENT_TOKEN_SALT in the users app's views.py
CLIENT_TOKEN_SALT = 'oauth-client-id-v1'
CLIENT_TOKEN_MAX_AGE = 60 * 10  # 10 minutes
CALLBACK_TIMEOUT_SECONDS = 5


def decode_client_token(client_id: str):
    """
    Verify and decode a signed client_id token.
    Raises ValueError with a user-facing message on any failure.
    """
    try:
        payload = signing.loads(client_id, salt=CLIENT_TOKEN_SALT, max_age=CLIENT_TOKEN_MAX_AGE)
    except SignatureExpired:
        raise ValueError('This authorization link has expired. Please generate a new one.')
    except BadSignature:
        raise ValueError('Invalid or tampered client token.')

    try:
        client = Client.objects.get(pk=payload['client_db_id'], is_active=True)
    except (Client.DoesNotExist, KeyError):
        raise ValueError('Client no longer exists or is inactive.')

    return payload, client


def trigger_callback_if_present(payload):
    print(payload)
    """
    Looks for payload['callback_info']['callback_url'].
    If found: POSTs the full payload['callback_info'] object as JSON body to that URL,
    using only the Python standard library (no external dependency required).
    If not found (either key missing): does nothing, no error raised.
    If the HTTP request itself fails: caught, no error raised.
    """
    result = {'attempted': False, 'success': False, 'detail': None}

    callback_info = payload.get('callback_info')
    if not isinstance(callback_info, dict):
        return result

    callback_url = callback_info.get('callback_url')
    if not callback_url or not isinstance(callback_url, str):
        return result

    result['attempted'] = True
    try:
        body = json.dumps(callback_info).encode('utf-8')
        req = urllib.request.Request(
            callback_url,
            data=body,
            headers={'Content-Type': 'application/json'},
            method='POST',
        )
        with urllib.request.urlopen(req, timeout=CALLBACK_TIMEOUT_SECONDS) as response:
            status_code = response.getcode()
            result['success'] = 200 <= status_code < 300
            result['detail'] = f'HTTP {status_code}'
    except urllib.error.HTTPError as exc:
        # Server responded with a non-2xx status
        result['success'] = False
        result['detail'] = f'HTTP {exc.code}'
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        # Network failure, DNS failure, timeout, malformed URL, etc.
        result['success'] = False
        result['detail'] = str(exc)

    return result


def _validate_txn(user, currency, amount, recipient_wallet=None):
    now = timezone.now()

    try:
        sender_wallet = Wallet.objects.get(user=user)
    except Wallet.DoesNotExist:
        return {'detail': 'Wallet not found.', 'code': 'wallet_not_found'}, None

    if not sender_wallet.is_active:
        return {
            'detail': 'Your account is currently inactive. Please contact support to reactivate.',
            'code': 'account_inactive'
        }, None

    if recipient_wallet is not None and not recipient_wallet.is_active:
        return {
            'detail': 'Recipient account is currently inactive. Transaction cannot be processed.',
            'code': 'recipient_inactive'
        }, None

    current_balance = getattr(sender_wallet, currency, None)
    if current_balance is None:
        return {'detail': f'Unsupported currency: {currency}', 'code': 'unsupported_currency'}, None

    if current_balance < amount:
        return {
            'detail': (
                f'Insufficient {currency} balance. '
                f'Available: {float(current_balance):,.2f}, '
                f'Required: {float(amount):,.2f}.'
            ),
            'code': 'insufficient_balance'
        }, None

    try:
        uc = user.currency_account
        remaining_daily = uc.max_lmt - uc.use_lmt
        if amount > remaining_daily:
            return {
                'detail': f'Daily transfer limit exceeded. Remaining limit today: ${float(remaining_daily):,.2f}.',
                'code': 'daily_limit_exceeded'
            }, None
    except Exception:
        pass

    last_30d = now - timedelta(days=30)
    monthly_volume = Transaction.objects.filter(
        user=user,
        status='completed',
        transaction_date__gte=last_30d
    ).aggregate(total=Sum('amount'))['total'] or Decimal('0')

    if monthly_volume + amount > MONTHLY_CAP:
        remaining_monthly = MONTHLY_CAP - monthly_volume
        return {
            'detail': f'Monthly transaction cap exceeded. Remaining monthly capacity: ${float(remaining_monthly):,.2f}.',
            'code': 'monthly_limit_exceeded'
        }, None

    return None, sender_wallet


class WalletView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        wallet, _ = Wallet.objects.get_or_create(
            user=request.user,
            defaults={
                'USD': Decimal('50000.00'),
                'EUR': Decimal('2400.00'),
                'JPY': Decimal('180000.00'),
                'GBP': Decimal('1500.00'),
                'preferred_currency': 'USD',
                'is_active': True,
            }
        )
        data = WalletSerializer(wallet).data
        try:
            uc = request.user.currency_account
            data['max_lmt'] = float(uc.max_lmt)
            data['use_lmt'] = float(uc.use_lmt)
        except Exception:
            data['max_lmt'] = 50000.0
            data['use_lmt'] = 0.0

        return Response(data)


class TransactionListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        transactions = Transaction.objects.filter(user=request.user).order_by('-transaction_date')
        serializer = TransactionSerializer(transactions, many=True)
        return Response(serializer.data)


class ConvertCurrencyView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        from_curr = request.data.get('from_currency', '').strip().upper()
        to_curr = request.data.get('to_currency', '').strip().upper()
        amount_str = request.data.get('amount')

        if not from_curr or not to_curr or amount_str is None:
            return Response(
                {'detail': 'from_currency, to_currency, and amount are required.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            amount = Decimal(str(amount_str))
        except (ValueError, TypeError):
            return Response({'detail': 'Invalid amount.'}, status=status.HTTP_400_BAD_REQUEST)

        if amount <= 0:
            return Response({'detail': 'Amount must be positive.'}, status=status.HTTP_400_BAD_REQUEST)

        if from_curr == to_curr:
            return Response(
                {'detail': 'Source and target currencies must be different.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        if from_curr not in SUPPORTED_CURRENCIES or to_curr not in SUPPORTED_CURRENCIES:
            return Response(
                {'detail': f'Unsupported currency pair: {from_curr}/{to_curr}.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        error, wallet = _validate_txn(request.user, from_curr, amount)
        if error:
            return Response(error, status=status.HTTP_400_BAD_REQUEST)

        history_list = CurrencyPriceHistory.objects.get_latest_price_history()
        if not history_list:
            return Response({'detail': 'Exchange rates unavailable.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        latest = history_list[0]
        rates = {
            'USD': Decimal('1.000000'),
            'EUR': Decimal(str(latest.EUR)),
            'JPY': Decimal(str(latest.JPY)),
            'GBP': Decimal(str(latest.GBP)),
        }

        rate_from = rates[from_curr]
        rate_to = rates[to_curr]
        amount_usd = amount / rate_from
        converted_amount = (amount_usd * (Decimal('1.0') - Decimal('0.004')) * rate_to).quantize(Decimal('0.01'))

        setattr(wallet, from_curr, getattr(wallet, from_curr) - amount)
        setattr(wallet, to_curr, getattr(wallet, to_curr) + converted_amount)
        wallet.save()

        try:
            uc = request.user.currency_account
            uc.use_lmt += amount
            uc.save(update_fields=['use_lmt', 'update_date_time'])
        except Exception:
            pass

        Transaction.objects.create(
            user=request.user,
            entity=f"{from_curr} to {to_curr} Conversion",
            transaction_date=timezone.now(),
            method=f"Internal FX Swap ({from_curr})",
            status='completed',
            amount=amount
        )

        return Response({
            'detail': 'Currency conversion successful.',
            'wallet': WalletSerializer(wallet).data,
            'converted_amount': float(converted_amount),
            'rate': float(rate_to / rate_from)
        })


class TransferView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        recipient_address = request.data.get('recipient', '').strip()
        currency = request.data.get('currency', 'USD').strip().upper()
        amount_str = request.data.get('amount')
        transfer_type = request.data.get('type', 'Peer Transfer')

        if not amount_str:
            return Response({'detail': 'amount is required.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            amount = Decimal(str(amount_str))
        except (ValueError, TypeError):
            return Response({'detail': 'Invalid amount.'}, status=status.HTTP_400_BAD_REQUEST)

        if amount <= 0:
            return Response({'detail': 'Amount must be positive.'}, status=status.HTTP_400_BAD_REQUEST)

        if currency not in SUPPORTED_CURRENCIES:
            return Response({'detail': f'Unsupported currency: {currency}.'}, status=status.HTTP_400_BAD_REQUEST)

        recipient_wallet = None
        if recipient_address:
            try:
                recipient_uc = UserCurrency.objects.select_related('user').get(
                    payment_address=recipient_address
                )
                try:
                    recipient_wallet = Wallet.objects.get(user=recipient_uc.user)
                except Wallet.DoesNotExist:
                    return Response(
                        {'detail': 'Recipient wallet not found.'},
                        status=status.HTTP_404_NOT_FOUND
                    )
            except UserCurrency.DoesNotExist:
                return Response(
                    {'detail': f'No account found with payment address "{recipient_address}". Please verify and try again.'},
                    status=status.HTTP_404_NOT_FOUND
                )

        error, sender_wallet = _validate_txn(request.user, currency, amount, recipient_wallet=recipient_wallet)
        if error:
            return Response(error, status=status.HTTP_400_BAD_REQUEST)

        setattr(sender_wallet, currency, getattr(sender_wallet, currency) - amount)
        sender_wallet.save()

        if recipient_wallet:
            setattr(recipient_wallet, currency, getattr(recipient_wallet, currency) + amount)
            recipient_wallet.save()

        try:
            uc = request.user.currency_account
            uc.use_lmt += amount
            uc.save(update_fields=['use_lmt', 'update_date_time'])
        except Exception:
            pass

        entity = f"Transfer to {recipient_address}" if recipient_address else "Peer Transfer"
        Transaction.objects.create(
            user=request.user,
            entity=entity,
            transaction_date=timezone.now(),
            method=f"{transfer_type} ({currency})",
            status='completed',
            amount=amount
        )

        return Response({
            'detail': 'Transfer completed successfully.',
            'wallet': WalletSerializer(sender_wallet).data,
        })


class PaymentView(APIView):
    """
    POST /api/wallet/payment/

    If `client_id` is provided in the request body, it's decoded using the
    signed-token mechanism. After the payment is successfully processed
    and recorded, if the decoded token payload contains
    callback_info.callback_url, a POST request is fired to that URL with
    the full callback_info object as the JSON body (via urllib, no
    external dependency).

    Missing client_id, invalid/expired token, missing callback_info, or
    missing callback_url are all silently skipped -- never an error.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        print("sasjkldjaklsdjkasldj")
        print(request.data)
        print("sasjkldjaklsdjkasldj")
        
        currency = request.data.get('currency', 'USD').strip().upper()
        amount_str = request.data.get('amount')
        entity = request.data.get('entity', 'Merchant Payment')
        method = request.data.get('method', 'Chain Hook Secure Pay')
        client_id = request.data.get('client_id')

        if amount_str is None:
            return Response({'detail': 'amount is required.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            amount = Decimal(str(amount_str))
        except (ValueError, TypeError):
            return Response({'detail': 'Invalid amount.'}, status=status.HTTP_400_BAD_REQUEST)

        if amount <= 0:
            return Response({'detail': 'Amount must be positive.'}, status=status.HTTP_400_BAD_REQUEST)

        if currency not in SUPPORTED_CURRENCIES:
            return Response({'detail': f'Unsupported currency: {currency}.'}, status=status.HTTP_400_BAD_REQUEST)

        # Decode token if provided. Any failure just means no callback later.
        token_payload = None
        if client_id:
            try:
                token_payload, _client = decode_client_token(client_id)
            except ValueError:
                token_payload = None

        error, wallet = _validate_txn(request.user, currency, amount)
        if error:
            return Response(error, status=status.HTTP_400_BAD_REQUEST)

        setattr(wallet, currency, getattr(wallet, currency) - amount)
        wallet.save()

        try:
            uc = request.user.currency_account
            uc.use_lmt += amount
            uc.save(update_fields=['use_lmt', 'update_date_time'])
        except Exception:
            pass

        Transaction.objects.create(
            user=request.user,
            entity=entity,
            transaction_date=timezone.now(),
            method=method,
            status='completed',
            amount=amount
        )

        tx_id = 'TX-' + ''.join([str(random.randint(0, 9)) for _ in range(8)])

        response_data = {
            'detail': 'Payment processed successfully.',
            'tx_id': tx_id,
            'wallet': WalletSerializer(wallet).data,
        }

        # Payment confirmed -- now attempt the callback.
        if token_payload:
            callback_result = trigger_callback_if_present(token_payload)
            if callback_result['attempted']:
                response_data['callback'] = callback_result
        
        return Response(response_data)


class CurrencyPriceHistoryView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        history = CurrencyPriceHistory.objects.get_latest_price_history(limit=50)
        serializer = CurrencyPriceHistorySerializer(history, many=True)
        return Response(serializer.data)


class WalletAnalyticsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        now = timezone.now()
        last_30d = now - timedelta(days=30)

        all_txs = Transaction.objects.filter(user=user)
        completed_txs = all_txs.filter(status='completed', transaction_date__gte=last_30d)
        pending_txs = all_txs.filter(status='pending')

        total_volume = float(completed_txs.aggregate(total=Sum('amount'))['total'] or 0)
        tx_count = completed_txs.count()
        pending_count = pending_txs.count()

        try:
            wallet = user.wallet
            rates = {'EUR': 1.09, 'JPY': 0.0068, 'GBP': 1.27}
            net_balance = wallet.get_total_balance_in_usd(rates)
        except Exception:
            net_balance = 0.0

        daily_volumes = []
        day_labels = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat']
        for i in range(6, -1, -1):
            day_start = now - timedelta(days=i)
            day_start = day_start.replace(hour=0, minute=0, second=0, microsecond=0)
            day_end = day_start + timedelta(days=1)
            day_total = all_txs.filter(
                status='completed',
                transaction_date__gte=day_start,
                transaction_date__lt=day_end
            ).aggregate(total=Sum('amount'))['total'] or 0
            daily_volumes.append({
                'name': day_labels[day_start.weekday() % 7],
                'amount': float(day_total)
            })

        portfolio_growth = []
        try:
            base_usd = float(user.wallet.USD)
        except Exception:
            base_usd = 50000.0

        for i in range(6, -1, -1):
            day_start = now - timedelta(days=i)
            label = day_start.strftime('%a')
            variation = base_usd * (0.98 + 0.04 * ((6 - i) / 6))
            portfolio_growth.append({'name': label, 'value': round(variation, 2)})

        market_trend = []
        price_history = CurrencyPriceHistory.objects.get_latest_price_history(limit=15)
        for ph in reversed(price_history):
            label = timezone.localtime(ph.create_date_time).strftime('%H:%M')
            market_trend.append({'name': label, 'value': float(ph.EUR)})

        currency_distribution = []
        try:
            w = user.wallet
            currency_distribution = [
                {'name': 'USD', 'value': round(float(w.USD), 2)},
                {'name': 'EUR', 'value': round(float(w.EUR) * 1.09, 2)},
                {'name': 'GBP', 'value': round(float(w.GBP) * 1.27, 2)},
                {'name': 'JPY', 'value': round(float(w.JPY) * 0.0068, 2)},
            ]
        except Exception:
            currency_distribution = [
                {'name': 'USD', 'value': 50000},
                {'name': 'EUR', 'value': 2616},
                {'name': 'GBP', 'value': 1905},
                {'name': 'JPY', 'value': 1224},
            ]

        holdings = []
        try:
            w = user.wallet
            holdings = [
                {'asset': 'USD', 'balance': float(w.USD), 'value_usd': float(w.USD)},
                {'asset': 'EUR', 'balance': float(w.EUR), 'value_usd': round(float(w.EUR) * 1.09, 2)},
                {'asset': 'GBP', 'balance': float(w.GBP), 'value_usd': round(float(w.GBP) * 1.27, 2)},
                {'asset': 'JPY', 'balance': float(w.JPY), 'value_usd': round(float(w.JPY) * 0.0068, 2)},
            ]
        except Exception:
            pass

        max_lmt = 50000.0
        use_lmt = 0.0
        try:
            uc = user.currency_account
            max_lmt = float(uc.max_lmt)
            use_lmt = float(uc.use_lmt)
        except Exception:
            pass

        return Response({
            'total_volume': total_volume,
            'tx_count': tx_count,
            'net_balance': net_balance,
            'pending_count': pending_count,
            'daily_volumes': daily_volumes,
            'portfolio_growth': portfolio_growth,
            'market_trend': market_trend,
            'currency_distribution': currency_distribution,
            'holdings': holdings,
            'max_lmt': max_lmt,
            'use_lmt': use_lmt,
        })
