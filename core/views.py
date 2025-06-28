from django.contrib import messages
from django.contrib.auth.models import User
from django.contrib.auth.tokens import default_token_generator
from django.contrib.sites.shortcuts import get_current_site
from django.core.exceptions import ObjectDoesNotExist
from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin
from django.db import IntegrityError
from django.shortcuts import render, get_object_or_404
from django.template.loader import render_to_string
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from django.views.generic import ListView, DetailView, View
from .models import *
from django.shortcuts import redirect
from django.utils import timezone
from .forms import *
from django.contrib.auth import authenticate, login as auth_login, logout as auth_logout
from django.conf import settings
from django.core.mail import send_mail
from django.utils.http import urlsafe_base64_decode
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth.models import User
from django.http import HttpResponse
from django.core.mail import EmailMultiAlternatives

import random
import stripe
import string

stripe.api_key = settings.STRIPE_SECRET_KEY


class HomeView(ListView):
    model = Item
    paginate_by = 4
    ordering = ['-id']
    template_name = "home.html"

    def get_queryset(self):
        queryset = super().get_queryset()
        query = self.request.GET.get('q')
        category = self.request.GET.get('category')  

        if query:
            queryset = queryset.filter(title__icontains=query)

        if category:  
            queryset = queryset.filter(category=category)  

        return queryset


# def products(request):
#     context = {"items": Item.objects.all()}
#     return render(request, "product.html", context)



def create_ref_code():
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=20))



def is_valid_form(values):
    valid = True
    for field in values:
        if field == '':
            valid = False
    return valid


class CheckoutView(View):
    def get(self, *args, **kwargs):
        try:
            order = Order.objects.get(user=self.request.user, ordered=False)
            form = CheckoutForm()
            coupon_form = CouponForm()
            context = {
                "form": form,
                "coupon_form": coupon_form,
                "order": order,
                "DISPLAY_COUPON_FORM": True
            }

            shipping_address_qs = Address.objects.filter(
                user=self.request.user,
                address_type='S',
                default=True
            )
            if shipping_address_qs.exists():
                context.update({'default_shipping_address': shipping_address_qs[0]})

            billing_address_qs = Address.objects.filter(
                user=self.request.user,
                address_type='B',
                default=True
            )
            if billing_address_qs.exists():
                context.update({'default_billing_address': billing_address_qs[0]})

            return render(self.request, "checkout.html", context)

        except ObjectDoesNotExist:
             return redirect("core:checkout")

    def post(self, *args, **kwargs):
        form = CheckoutForm(self.request.POST or None)

        try:
            order = Order.objects.get(user=self.request.user, ordered=False)
            shipping_address = None
            if form.is_valid():

                use_default_shipping = form.cleaned_data.get('use_default_shipping')
                if use_default_shipping:
                    print("Using the default shipping address")
                    address_qs = Address.objects.filter(
                        user=self.request.user,
                        address_type='S',
                        default=True
                    )
                    if address_qs.exists():
                        shipping_address = address_qs[0]
                        order.shipping_address = shipping_address
                        order.save()
                    else:
                        messages.info(self.request, "No default shipping address available")
                        return redirect('core:checkout')
                else:
                    print("User is entering a new shipping address")
                    shipping_address1 = form.cleaned_data.get('shipping_address')
                    shipping_address2 = form.cleaned_data.get('shipping_address2')
                    shipping_country = form.cleaned_data.get('shipping_country')
                    shipping_zip = form.cleaned_data.get('shipping_zip')

                    if is_valid_form([shipping_address1, shipping_country, shipping_zip]):
                        shipping_address = Address(
                            user=self.request.user,
                            street_address=shipping_address1,
                            apartment_address=shipping_address2,
                            country=shipping_country,
                            zip=shipping_zip,
                            address_type='S'
                        )
                        shipping_address.save()

                        order.shipping_address = shipping_address
                        order.save()

                        set_default_shipping = form.cleaned_data.get("set_default_shipping")
                        if set_default_shipping:
                            shipping_address.default = True
                            shipping_address.save()
                    else:
                        messages.info(self.request, "Please fill in the required shipping address fields")

                use_default_billing = form.cleaned_data.get('use_default_billing')
                same_billing_address = form.cleaned_data.get('same_billing_address')

                if same_billing_address:
                    billing_address = shipping_address
                    billing_address.pk = None
                    billing_address.save()
                    billing_address.address_type = 'B'
                    billing_address.save()
                    order.billing_address = billing_address
                    order.save()

                elif use_default_billing:
                    print("Using the default billing address")
                    address_qs = Address.objects.filter(
                        user=self.request.user,
                        address_type='B',
                        default=True
                    )
                    if address_qs.exists():
                        billing_address = address_qs[0]
                        order.billing_address = billing_address
                        order.save()
                    else:
                        messages.info(self.request, "No default billing address available")
                        return redirect('core:checkout')
                else:
                    print("User is entering a new billing address")
                    billing_address1 = form.cleaned_data.get('billing_address')
                    billing_address2 = form.cleaned_data.get('billing_address2')
                    billing_country = form.cleaned_data.get('billing_country')
                    billing_zip = form.cleaned_data.get('billing_zip')

                    if is_valid_form([billing_address1, billing_country, billing_zip]):
                        billing_address = Address(
                            user=self.request.user,
                            street_address=billing_address1,
                            apartment_address=billing_address2,
                            country=billing_country,
                            zip=billing_zip,
                            address_type='B'
                        )
                        billing_address.save()

                        order.billing_address = billing_address
                        order.save()

                        set_default_billing = form.cleaned_data.get("set_default_billing")
                        if set_default_billing:
                            billing_address.default = True
                            billing_address.save()
                    else:
                        messages.info(self.request, "Please fill in the required billing address fields")

                payment_option = form.cleaned_data.get('payment_option')

                if payment_option == "stripe":
                    return redirect('core:payment', payment_option="stripe")
                elif payment_option == "paypal":
                    return redirect('core:payment', payment_option="paypal")
                else:
                    messages.warning(self.request, "Invalid payment option selected")
                    return redirect("core:checkout")

            messages.warning(self.request, "Failed checkout")
            return redirect('core:checkout')

        except ObjectDoesNotExist:
            messages.warning(self.request, "You do not have an active order")
            return redirect("core:order-summary")


class PaymentView(View):
    def get(self, *args, **kwargs):
        order = Order.objects.get(user=self.request.user, ordered=False)
        if order.billing_address:
            context = {
                'STRIPE_PUBLIC_KEY': settings.STRIPE_PUBLIC_KEY,
                'order': order,
                "DISPLAY_COUPON_FORM": False
            }
            return render(self.request, "payment.html", context)
        else:
            messages.warning(self.request, "You have not added a billing address")
            return redirect("core:checkout")

    def post(self, *args, **kwargs):
        order = Order.objects.get(user=self.request.user, ordered=False)
        token = self.request.POST.get('stripeToken')
        amount = int(order.get_total() * 100)

        try:
            charge = stripe.Charge.create(
                amount=amount,
                currency="usd",
                source=token
            )

            payment = Payment()
            payment.stripe_charge_id = charge['id']
            payment.user = self.request.user
            payment.amount = order.get_total()
            payment.save()

            order_items = order.items.all()
            order_items.update(ordered=True)
            for item in order_items:
                item.save()

            order.ordered = True
            order.payment = payment
            order.ref_code = create_ref_code()
            order.save()

            messages.success(self.request, "Your order was successful!")
            return redirect("/")

        except stripe.error.CardError as e:
            body = e.json_body
            err = body.get('error', {})
            messages.warning(self.request, f"{err.get('message')}")
            return redirect("/")

        except stripe.error.RateLimitError as e:
            messages.warning(self.request, "Rate limit error")
            return redirect("/")

        except stripe.error.InvalidRequestError as e:
            messages.warning(self.request, "Invalid parameters")
            return redirect("/")

        except stripe.error.AuthenticationError as e:
            messages.warning(self.request, "Not authenticated")
            return redirect("/")

        except stripe.error.APIConnectionError as e:
            messages.warning(self.request, "Network error")
            return redirect("/")

        except stripe.error.StripeError as e:
            messages.warning(self.request, "Something went wrong. You were not charged. Please try again.")
            return redirect("/")

        except Exception as e:
            print(f"error{e}")
            messages.warning(self.request, "A serious error occurred.")
            return redirect("/")



class OrderSummaryView(LoginRequiredMixin, View):
    def get(self, *args, **kwargs):
        try:
            order = Order.objects.get(user=self.request.user, ordered=False)
            context = {
                'object': order,
            }
            return render(self.request, "order_summary.html", context)
        except ObjectDoesNotExist:
            messages.warning(self.request, "You do not have an active order")
            return redirect("/")


class ItemDetailView(DetailView):
    model = Item
    template_name = "product.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        item = self.get_object()
        is_in_cart = False
        if self.request.user.is_authenticated:
            try:
                user_order = Order.objects.get(user=self.request.user, ordered=False)
                if user_order.items.filter(item=item).exists():
                    is_in_cart = True
            except ObjectDoesNotExist:
                is_in_cart = False
        context['object'].is_in_cart = is_in_cart
        context["form"] = AddToCartForm()
        return context


@login_required
def add_to_cart(request, slug):
    item = get_object_or_404(Item, slug=slug)

    if request.method == "POST":
        # User is adding from product page with a form (size selected)
        form = AddToCartForm(request.POST)
        if form.is_valid():
            selected_size = form.cleaned_data.get("size")
        else:
            messages.error(request, "Invalid form submission.")
            return redirect("core:product", slug=slug)
    else:
        # User is adding from cart quantity increment button (GET)
        # Find an existing order item for this user and product
        order_item_qs = OrderItem.objects.filter(
            item=item, user=request.user, ordered=False
        )
        if order_item_qs.exists():
            # Just pick the first existing order item (with its size)
            existing_order_item = order_item_qs.first()
            selected_size = existing_order_item.size
        else:
            # No existing order item, fallback to default size or redirect with error
            messages.error(request, "Please select a size to add this item.")
            return redirect("core:product", slug=slug)

    # Now get or create the order item with correct size
    order_item, created = OrderItem.objects.get_or_create(
        item=item,
        user=request.user,
        ordered=False,
        size=selected_size,
    )

    order_qs = Order.objects.filter(user=request.user, ordered=False)

    if order_qs.exists():
        order = order_qs[0]

        # Check if order already contains this item with this size
        if order.items.filter(item__slug=item.slug, size=selected_size).exists():
            order_item.quantity += 1
            order_item.save()
            messages.info(request, "This item quantity was updated")
        else:
            order.items.add(order_item)
            messages.info(request, "This item was successfully added to the cart")
    else:
        ordered_date = timezone.now()
        order = Order.objects.create(user=request.user, ordered_date=ordered_date)
        order.items.add(order_item)
        messages.info(request, "This item was successfully added to the cart")

    referer_url = request.META.get('HTTP_REFERER', '/')
    if 'order-summary' in referer_url:
        return redirect("core:order-summary")
    else:
        return redirect("core:product", slug=slug)


@login_required
def remove_from_cart(request, slug):
    item = get_object_or_404(Item, slug=slug)
    order_qs = Order.objects.filter(user=request.user, ordered=False)

    if order_qs.exists():
        order = order_qs[0]

        if order.items.filter(item__slug=item.slug).exists():
            order_item = OrderItem.objects.filter(
                item=item, user=request.user, ordered=False
            )[0]

            if order_item.quantity > 1:
                order_item.quantity -= 1
                order_item.save()
                messages.info(request, f"Decreased the quantity of {item.title}")
            else:
                order.items.remove(order_item)
                order_item.delete()
                messages.info(
                    request, "This item was successfully removed from the cart"
                )
        else:
            messages.info(request, "This item was not in your cart")
    else:
        messages.info(request, "You do not have an active order")

    referer_url = request.META.get('HTTP_REFERER')
    if referer_url and 'order-summary' in referer_url:
        return redirect("core:order-summary")
    else:
        return redirect("core:product", slug=slug)


@login_required
def remove_all_from_cart(request, slug):
    item = get_object_or_404(Item, slug=slug)
    order_qs = Order.objects.filter(user=request.user, ordered=False)

    if order_qs.exists():
        order = order_qs[0]
        if order.items.filter(item__slug=item.slug).exists():
            order_item = OrderItem.objects.filter(
                item=item,
                user=request.user,
                ordered=False
            )[0]
            order.items.remove(order_item)
            order_item.delete()  
            messages.info(request, "This item was removed from your cart.")
        else:
            messages.info(request, "This item was not in your cart.")
    else:
        messages.info(request, "You do not have an active order.")

    return redirect("core:order-summary")


def custom_login(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)
        if user is not None:
            auth_login(request, user)
            messages.info(request, f"You have been logged in as {user.username}")
            print(request.user.is_authenticated)
            return redirect('/') 
        else:
            messages.warning(request, 'Invalid username or password.')

    form = LoginForm()
    context = {
        'form': form,
        'signup_url': reverse('core:account_signup'),
    }
    return render(request, "accounts/login.html", context)


def logout(request):
    return render(request, "accounts/logout.html")


def custom_logout(request):
    if request.user.is_authenticated:
        auth_logout(request)
        messages.info(request, 'You have been logged out.')
    return redirect('/')


def signup(request):
    if request.method == 'POST':
        form = SignupForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            email = form.cleaned_data.get('email')
            password = form.cleaned_data['password1']
            password2 = form.cleaned_data['password2']

            if password != password2:
                messages.error(request, "Passwords do not match.")
                return render(request, "accounts/signup.html", {'form': form})

            try:
                user = User.objects.create_user(username=username, email=email, password=password)
                user.is_active = False
                user.save()

                messages.success(request, f"Account created for {user.username}! Check your email to activate your account.")

                current_site = get_current_site(request)
                domain = current_site.domain
                protocol = 'https' if request.is_secure() else 'http'

                subject = 'Activate Your Account'

                html_content = render_to_string('activation_email.html', {
                    'user': user,
                    'domain': domain,
                    'protocol': protocol,
                    'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                    'token': default_token_generator.make_token(user),
                })

                uid = urlsafe_base64_encode(force_bytes(user.pk))
                if isinstance(uid, bytes):
                    uid = uid.decode()

                token = default_token_generator.make_token(user)

                text_content = (
                    f"Welcome, {user.username}!\n\n"
                    f"Thanks for signing up. To complete your registration, please confirm your email address by visiting the following link:\n\n"
                    f"{protocol}://{domain}/activate/{uid}/{token}/\n\n"
                    f"If you did not create an account, no further action is required."
                )

                msg = EmailMultiAlternatives(subject, text_content, 'noreply@yourdomain.com', [email])
                msg.attach_alternative(html_content, "text/html")
                msg.send()

                return redirect(reverse('core:account_login'))

            except IntegrityError:
                messages.error(request, "A user with that username already exists.")
                return render(request, "accounts/signup.html", {'form': form})
            except Exception as e:
                messages.error(request, f"An unexpected error occurred during signup: {e}")
                return render(request, "accounts/signup.html", {'form': form})
        else:
            messages.error(request, "There was an error with your sign-up. Please correct the errors below.")
    else:
        form = SignupForm()

    return render(request, "accounts/signup.html", {'form': form})


def activate(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user is not None and default_token_generator.check_token(user, token):
        user.is_active = True
        user.save()
        messages.success(request, "Thank you for your email confirmation. You can now log in.")
        return redirect('core:account_login')
    else:
        messages.error(request, "Activation link is invalid!")
        return redirect('core:account_login')


def get_coupon(request, code):
    try:
        coupon = Coupon.objects.get(code=code)
        return coupon
    except:
        messages.info(request, "This coupon does not exists")
        return redirect("core:checkout")


class AddCouponView(View):
    def post(self, *args, **kwargs):
        form = CouponForm(self.request.POST or None)
        print("POST data:", self.request.POST)  # Debug
        print("Is form valid?", form.is_valid())  # Debug

        if form.is_valid():
            try:
                code = form.cleaned_data.get('code')
                print("Coupon code:", code)
                order = Order.objects.get(user=self.request.user, ordered=False)
                order.coupon = get_coupon(self.request, code)
                order.save()
                messages.success(self.request, "Successfully added coupon")
                return redirect("core:checkout")
            except ObjectDoesNotExist:
                messages.info(self.request, "You don't have an active order")
                return redirect("core:checkout")
        else:
            print("Form errors:", form.errors)
            messages.error(self.request, "Invalid coupon code")
            return redirect("core:checkout")



class RequestRefundView(View):

    def get(self, *args, **kwargs):
        form = RefundForm()
        context = {
            'form': form
        }
        return render(self.request, "request_refund.html", context)

    def post(self, *args, **kwargs):
        form = RefundForm(self.request.POST)
        if form.is_valid():
            ref_code = form.cleaned_data.get('ref_code')
            message = form.cleaned_data.get('message')
            email = form.cleaned_data.get('email')

            try:
                order = Order.objects.get(ref_code=ref_code)
                order.refund_requested = True
                order.save()

                refund = Refund()
                refund.order = order
                refund.reason = message
                refund.email = email
                refund.save()

                messages.info(self.request, "You have requested a refund")
                return redirect("core:request-refund")

            except ObjectDoesNotExist:
                messages.info(self.request, "This order does not exist")
                return redirect("core:request-refund")


class OrderHistoryView(LoginRequiredMixin, ListView):
    model = Order
    template_name = "order_history.html"
    context_object_name = "orders"
    ordering = ['-ordered_date'] 
    paginate_by = 5 

    def get_queryset(self):
        return Order.objects.filter(user=self.request.user, ordered=True)

