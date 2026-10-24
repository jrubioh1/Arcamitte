import re
from typing import Any

from django import forms
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _

from arcamitte.models import OrganizationalUnit
from arcamitte.validators import validate_safe_email

User = get_user_model()

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
                "class": "form-control font-mono text-center fs-3 fw-bold",
                "style": "letter-spacing: 0.35rem;",
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


class OrganizationalUnitForm(forms.ModelForm):
    """
    Formulario para creación y edición de Unidades Organizativas.
    Adapta los campos disponibles en función de si el usuario es superusuario o admin de UO.
    """

    class Meta:
        model = OrganizationalUnit
        fields = ["numeric_code", "alias", "name", "email", "description", "is_active"]
        widgets = {
            "numeric_code": forms.NumberInput(attrs={"class": "form-control", "placeholder": "1001"}),
            "alias": forms.TextInput(attrs={"class": "form-control text-uppercase font-mono", "placeholder": "LEGAL"}),
            "name": forms.TextInput(attrs={"class": "form-control", "placeholder": _("Asesoría Jurídica y Cumplimiento")}),
            "email": forms.EmailInput(attrs={"class": "form-control", "placeholder": "legal@empresa.com"}),
            "description": forms.Textarea(attrs={"class": "form-control", "rows": 3}),
            "is_active": forms.CheckboxInput(attrs={"class": "form-check-input"}),
        }

    def __init__(self, *args: Any, is_superuser: bool = False, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.is_superuser = is_superuser
        if not is_superuser:
            # Los administradores de UO no pueden alterar el código ni el alias ya fijados
            if "numeric_code" in self.fields:
                self.fields["numeric_code"].disabled = True
            if "alias" in self.fields:
                self.fields["alias"].disabled = True
            if "is_active" in self.fields:
                self.fields["is_active"].disabled = True

    def clean_alias(self) -> str:
        alias = (self.cleaned_data.get("alias") or "").strip().upper()
        if not re.match(r"^[A-Z0-9_\-]+$", alias):
            raise ValidationError(_("El alias solo puede contener letras mayúsculas, números y guiones."))
        return alias


class UserManagementForm(forms.ModelForm):
    """
    Formulario de administración de cuentas de usuario.
    Permite gestionar datos personales, estado activo y roles globales.
    """

    class Meta:
        model = User
        fields = ["username", "email", "first_name", "last_name", "is_active"]
        widgets = {
            "username": forms.TextInput(attrs={"class": "form-control font-mono"}),
            "email": forms.EmailInput(attrs={"class": "form-control"}),
            "first_name": forms.TextInput(attrs={"class": "form-control"}),
            "last_name": forms.TextInput(attrs={"class": "form-control"}),
            "is_active": forms.CheckboxInput(attrs={"class": "form-check-input"}),
        }

    def __init__(self, *args: Any, is_superuser: bool = False, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.is_superuser = is_superuser
        if is_superuser:
            self.fields["is_staff"] = forms.BooleanField(
                required=False,
                label=_("Acceso administrativo (is_staff)"),
                widget=forms.CheckboxInput(attrs={"class": "form-check-input"}),
                initial=getattr(self.instance, "is_staff", False),
            )
            self.fields["is_superuser"] = forms.BooleanField(
                required=False,
                label=_("Superusuario global (is_superuser)"),
                widget=forms.CheckboxInput(attrs={"class": "form-check-input"}),
                initial=getattr(self.instance, "is_superuser", False),
            )

    def clean_email(self) -> str:
        raw_email = self.cleaned_data.get("email", "")
        return validate_safe_email(raw_email)

    def save(self, commit: bool = True) -> Any:
        user = super().save(commit=False)
        if self.is_superuser:
            user.is_staff = self.cleaned_data.get("is_staff", False)
            user.is_superuser = self.cleaned_data.get("is_superuser", False)
        if commit:
            user.save()
        return user


class PasswordResetRequestForm(forms.Form):
    """
    Formulario de autoservicio para solicitud de reseteo de contraseña olvidada.
    """

    identity = forms.CharField(
        label=_("Usuario o Correo Electrónico"),
        widget=forms.TextInput(
            attrs={
                "class": "form-control form-control-lg",
                "placeholder": _("su_usuario o nombre@empresa.com"),
                "autocomplete": "username",
                "autofocus": "autofocus",
            }
        ),
        help_text=_("Introduzca su nombre de usuario o la dirección de correo corporativa vinculada a su cuenta."),
    )

    def clean_identity(self) -> str:
        return (self.cleaned_data.get("identity") or "").strip()


class PasswordChangeCustomForm(forms.Form):
    """
    Formulario para actualización obligatoria o voluntaria de contraseña.
    Aplica directivas estrictas de complejidad y confirmación.
    """

    current_password = forms.CharField(
        label=_("Contraseña Actual / Temporal"),
        widget=forms.PasswordInput(
            attrs={
                "class": "form-control",
                "autocomplete": "current-password",
                "placeholder": "••••••••••••",
            }
        ),
    )
    new_password = forms.CharField(
        label=_("Nueva Contraseña"),
        widget=forms.PasswordInput(
            attrs={
                "class": "form-control",
                "autocomplete": "new-password",
                "placeholder": "••••••••••••",
            }
        ),
        help_text=_("Debe contener al menos 8 caracteres y cumplir las directivas de seguridad corporativas."),
    )
    confirm_password = forms.CharField(
        label=_("Confirmar Nueva Contraseña"),
        widget=forms.PasswordInput(
            attrs={
                "class": "form-control",
                "autocomplete": "new-password",
                "placeholder": "••••••••••••",
            }
        ),
    )

    def __init__(self, user: Any, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.user = user

    def clean_current_password(self) -> str:
        current_password = self.cleaned_data.get("current_password", "")
        if not self.user.check_password(current_password):
            raise ValidationError(_("La contraseña actual o temporal no es correcta."))
        return current_password

    def clean(self) -> dict[str, Any]:
        cleaned_data = super().clean()
        new_password = cleaned_data.get("new_password")
        confirm_password = cleaned_data.get("confirm_password")

        if new_password and confirm_password:
            if new_password != confirm_password:
                self.add_error("confirm_password", _("Las nuevas contraseñas no coinciden."))
            else:
                try:
                    validate_password(new_password, user=self.user)
                except ValidationError as exc:
                    self.add_error("new_password", exc)

        return cleaned_data

