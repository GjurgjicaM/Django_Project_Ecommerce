from django import forms
from django_countries.fields import CountryField
from django_countries.widgets import CountrySelectWidget

payment_options = [("stripe", "Stripe"), ("paypal", "PayPal")]


class LoginForm(forms.Form):
    username = forms.CharField(
        label="Username:", widget=forms.TextInput(attrs={"placeholder": "Username"})
    )
    password = forms.CharField(
        label="Password:", widget=forms.PasswordInput(attrs={"placeholder": "Password"})
    )
    remember = forms.BooleanField(label="Remember me:", required=False)


class SignupForm(forms.Form):
    username = forms.CharField(
        label="Username:", widget=forms.TextInput(attrs={"placeholder": "Username"})
    )
    email = forms.CharField(
        label="E-Mail(optional):",
        required=False,
        widget=forms.TextInput(attrs={"placeholder": "E-mail address"}),
    )
    password1 = forms.CharField(
        label="Password:", widget=forms.PasswordInput(attrs={"placeholder": "Password"})
    )
    password2 = forms.CharField(
        label="Password(again):",
        widget=forms.PasswordInput(attrs={"placeholder": "Password(again)"}),
    )


class CheckoutForm(forms.Form):
    shipping_address = forms.CharField(required=False)
    shipping_address2 = forms.CharField(required=False)
    shipping_country = CountryField(blank_label="(select country)").formfield(
        attrs={"class": "custom-select d-block w-100"},
        widget=CountrySelectWidget(attrs={"class": "custom-select d-block w-100"}),
        required=False,
    )
    shipping_zip = forms.CharField(required=False)

    billing_address = forms.CharField(required=False)
    billing_address2 = forms.CharField(required=False)
    billing_country = CountryField(blank_label="(select country)").formfield(
        required=False,
        attrs={"class": "custom-select d-block w-100"},
        widget=CountrySelectWidget(attrs={"class": "custom-select d-block w-100"})
    )
    billing_zip = forms.CharField(required=False)

    same_billing_address = forms.BooleanField(required=False)
    set_default_shipping = forms.BooleanField(required=False)
    use_default_shipping = forms.BooleanField(required=False)
    set_default_billing = forms.BooleanField(required=False)
    use_default_billing = forms.BooleanField(required=False)

    payment_option = forms.ChoiceField(choices=payment_options, widget=forms.RadioSelect)


class CouponForm(forms.Form):
    code = forms.CharField(widget=forms.TextInput(attrs={"class": "form-control", "placeholder": "Promo code"}))


class RefundForm(forms.Form):
    ref_code = forms.CharField(max_length=20)
    message = forms.CharField(widget=forms.Textarea(attrs={"rows": "4"}))
    email = forms.EmailField()
