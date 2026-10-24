import re
from django import forms
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _

from arcamitte.validators import validate_safe_email

HASH_REGEX = re.compile(r"^[0-9a-fA-F]{64}$")


class RequestAccessForm(forms.Form):
    """
    Formulario público para solicitar el canje desatendido mediante Hash SHA-256 y OTP.

    Regla de Oro 1: CERO TRANSPORTE DEL BINARIO POR EL CLIENTE.
    El usuario final NUNCA sube el archivo .enc para identificarse.
    El localizador oficial y prueba de trámite es exclusivamente el hash SHA-256.
    """

    file_hash = forms.CharField(
        label=_("Identificador del Documento (Hash SHA-256)"),
        max_length=64,
        min_length=64,
        widget=forms.TextInput(
            attrs={
                "class": "form-control font-mono",
                "placeholder": _("Cadena hexadecimal de 64 caracteres"),
                "id": "file_hash",
                "autocomplete": "off",
                "spellcheck": "false",
            }
        ),
        help_text=_("Identificador de 64 caracteres facilitado para la descarga del documento."),
    )
    email = forms.EmailField(
        label=_("Correo Electrónico"),
        widget=forms.EmailInput(
            attrs={
                "class": "form-control",
                "placeholder": _("su-correo@empresa.com"),
                "id": "email",
                "autocomplete": "off",
            }
        ),
        help_text=_("Dirección de correo autorizada donde recibirá el código de verificación."),
    )

    def clean_file_hash(self) -> str:
        raw_hash = (self.cleaned_data.get("file_hash") or "").strip().lower()
        if not HASH_REGEX.match(raw_hash):
            raise ValidationError(
                _("El identificador SHA-256 debe componerse de 64 caracteres hexadecimales [0-9a-f].")
            )
        return raw_hash

    def clean_email(self) -> str:
        raw_email = self.cleaned_data.get("email", "")
        return validate_safe_email(raw_email)


class RedeemOtpForm(forms.Form):
    """
    Formulario para la descarga y verificación mediante código de 6 dígitos.
    """

    file_hash = forms.CharField(
        max_length=64,
        min_length=64,
        widget=forms.HiddenInput(attrs={"id": "redeem_file_hash"}),
        required=True,
    )
    email = forms.EmailField(
        widget=forms.HiddenInput(attrs={"id": "redeem_email"}),
        required=True,
    )
    otp_code = forms.CharField(
        label=_("Código de Verificación (6 dígitos)"),
        max_length=6,
        min_length=6,
        widget=forms.TextInput(
            attrs={
                "class": "form-control font-mono text-center",
                "placeholder": "123456",
                "id": "otp_code",
                "maxlength": "6",
                "autocomplete": "one-time-code",
                "autofocus": "autofocus",
            }
        ),
        help_text=_("Introduzca el código de 6 dígitos recibido en su correo electrónico."),
    )

    def clean_file_hash(self) -> str:
        raw_hash = (self.cleaned_data.get("file_hash") or "").strip().lower()
        if not HASH_REGEX.match(raw_hash):
            raise ValidationError(_("El identificador SHA-256 no es válido."))
        return raw_hash

    def clean_email(self) -> str:
        raw_email = self.cleaned_data.get("email", "")
        return validate_safe_email(raw_email)

    def clean_otp_code(self) -> str:
        code = (self.cleaned_data.get("otp_code") or "").strip()
        if not code.isdigit() or len(code) != 6:
            raise ValidationError(_("El código de verificación debe contener 6 dígitos numéricos."))
        return code

