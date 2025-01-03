from django.db import models

# Create your models here.
from django.contrib.auth.base_user import BaseUserManager, AbstractBaseUser
from django.contrib.auth.models import PermissionsMixin
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from django.urls import reverse
from django.core.mail import send_mail
import binascii, os
from django.core.exceptions import ValidationError
from django.template.loader import render_to_string
from django.core.mail.message import EmailMultiAlternatives
import phonenumbers
from django.conf import settings

"""" For path of model that are editable """
EXPIRY_PERIOD = 3    # days

def _generate_code():
    """ to generate token code"""
    return binascii.hexlify(os.urandom(20)).decode('utf-8')

# fields.py
from django.db import models
from django.core.exceptions import ValidationError


class MultiSelectField1(models.TextField):
    description = "A custom field to store multiple choices"

    def __init__(self, *args, **kwargs):
        self.choices = kwargs.pop('choices', [])
        super().__init__(*args, **kwargs)

    def from_db_value(self, value, expression, connection):
        if not value:
            return []
        return value.split(',')

    def to_python(self, value):
        if not value:
            return []
        if isinstance(value, list):
            return value
        return value.split(',')

    def get_prep_value(self, value):
        if not value:
            return ''
        return ','.join(value)

    def validate(self, value, model_instance):
        super().validate(value, model_instance)
        choices = [choice[0] for choice in self.choices]
        for val in value:
            if val not in choices:
                raise ValidationError(f'{val} is not a valid choice.')

    def formfield(self, **kwargs):
        from django import forms
        defaults = {
            'form_class': forms.MultipleChoiceField,
            'choices': self.choices,
        }
        defaults.update(kwargs)
        return super().formfield(**defaults)


class PhoneNumberField(models.CharField):
    description = "International phone number"

    def __init__(self, *args, **kwargs):
        kwargs['max_length'] = 15  # Maximum length for international numbers
        super().__init__(*args, **kwargs)

    def to_python(self, value):
        if value in self.empty_values:
            return None
        return str(value)

    def validate(self, value, model_instance):
        super().validate(value, model_instance)
        if not self.is_valid_phone_number(value):
            raise ValidationError(f'{value} is not a valid phone number.')

    def is_valid_phone_number(self, value):
        try:
            parsed_number = phonenumbers.parse(value, None)
            return phonenumbers.is_valid_number(parsed_number)
        except phonenumbers.NumberParseException:
            return False


class LowerCaseEmailField(models.EmailField):
    """
    OVERRIDE EMAIL FIELD TO SET IT TO LOWERCASE BEFORE SAVING.
    """

    def to_python(self, value):
        """ 
        convert email to lowercase 
        """
        value = super(LowerCaseEmailField, self).to_python(value)
        # check if value is a string (is not None)
        if isinstance(value, str):
            return value.lower()
        return value
    

class UserManager(BaseUserManager):
    """ User Manager for creation of user."""
    def _create_user(self, email, password, is_staff, is_superuser,
                     is_verified, **extra_fields):
        """
        Creates and saves a User with a given email and password.
        """
        now = timezone.now()
        if not email:
            raise ValueError('Users must have an email address')
        email = self.normalize_email(email)
        user = self.model(email=email,
                          is_staff=is_staff, is_active=True,
                          is_superuser=is_superuser, is_verified=is_verified,
                          last_login=now, date_joined=now, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_user(self, email, password=None, **extra_fields):
        return self._create_user(email, password, False, False, False,
                                 **extra_fields)

    def create_superuser(self, email, password=None, **extra_fields):
        return self._create_user(email, password, True, True, True,
                                 **extra_fields)
    

class Status(models.IntegerChoices):
    """
    This class is use as flag allowing to define the status of model
    """
    ACTIVE = 1, _('Active')
    DEACTIVATED = 2, _('Deactivated')
    SUSPENDED = 3, _('Suspend')

class User(AbstractBaseUser, PermissionsMixin):
    objects = UserManager()
    country = models.CharField(max_length=255, blank=True)
    username = models.CharField(_("username"), max_length=150, unique=True)
    first_name = models.CharField(_("first name"), max_length=150, blank=True)
    last_name = models.CharField(_("last name"), max_length=150, blank=True)
    email = LowerCaseEmailField(
        _("email address"),
        unique=True,
        error_messages={
            "unique": _("A user with that email already exists."),
        },
    )

    status = models.IntegerField(choices=Status.choices, default=Status.ACTIVE)
    date_joined = models.DateTimeField(_("date joined"), default=timezone.now)

    is_verified = models.BooleanField(
        _('verified'), default=False,
        help_text=_('Designates whether this user has completed the email '
                    'verification process to allow login.')
    )
    is_staff = models.BooleanField(
        _("staff status"),
        default=False,
        help_text=_(
            "Designates whether the user can log into this admin site."),
    )
    is_active = models.BooleanField(
        _("active"),
        default=True,
        help_text=_(
            "Designates whether this user should be treated as active. "
            "Unselect this instead of deleting accounts."
        ),
    )
    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ['username',]


    class Meta:
        verbose_name = _('user')
        verbose_name_plural = _('users')
        # fields = ['user_status']

    def __str__(self):
        """ user description """
        return self.email
    
    def clean(self):
        super().clean()
        self.email = self.__class__.objects.normalize_email(self.email)
    def get_full_name(self):
        """
        Return the first_name plus the last_name, with a space in between.
        """
        full_name = "%s %s" % (self.first_name, self.last_name)
        return full_name.strip()

    def get_short_name(self):
        """Return the short name for the user."""
        return self.first_name

    def email_user(self, subject, message, from_email=None, **kwargs):
        """Send an email to this user."""
        send_mail(subject, message, from_email, [self.email], **kwargs)

    def get_absolute_url(self):
        return reverse('user-detail', args=[str(self.pk)])

class SignupCodeManager(models.Manager):
    def create_signup_code(self, user, ipaddr):
        code = _generate_code()
        signup_code = self.create(user=user, code=code, ipaddr=ipaddr)

        return signup_code

    def set_user_is_verified(self, code):
        try:
            signup_code = SignupCode.objects.get(code=code)
            signup_code.user.is_verified = True
            signup_code.user.save()
            return True
        except SignupCode.DoesNotExist:
            pass

        return False

class AbstractBaseCode(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    code = models.CharField(_('code'), max_length=40, primary_key=True)
    created_at = models.DateTimeField(auto_now_add=True)
    class Meta:
        abstract = True

    def send_email(self, prefix):
        ctxt = {
            'email': self.user.email,
            'username': self.user.username,
            'last_name': self.user.last_name,
            'first_name': self.user.first_name,
            'code': self.code,
            # 'phone_number': self.user.phone_number
        }
        send_multi_format_email(prefix, ctxt, target_email=self.user.email)

    def __str__(self):
        return self.code


class SignupCode(AbstractBaseCode):
    ipaddr = models.GenericIPAddressField(_('ip address'))
    objects = SignupCodeManager()

    def send_signup_email(self):
        prefix = 'signup_email'
        self.send_email(prefix)

    def send_signup_verify(self, prefix):
        self.send_email(prefix)



class PasswordResetCodeManager(models.Manager):
    def create_password_reset_code(self, user, new_password):
        code = _generate_code()
        password_reset_code = self.create(user=user, code=code, new_password=new_password)

        return password_reset_code

    def get_expiry_period(self):
        return EXPIRY_PERIOD
    

class PasswordResetCode(AbstractBaseCode):
    objects = PasswordResetCodeManager()
    new_password = models.CharField(max_length=255)

    def change_user_password(self):
        user = self.user
        password = self.new_password
        user.set_password(password)
        user.save()

    def send_password_reset_email(self):
        prefix = 'password_reset_email'
        self.send_email(prefix)

    def set_user_is_verified(self, code):
        try:
            password_reset_code = PasswordResetCode.objects.get(code=code)
            return True
        except SignupCode.DoesNotExist:
            pass

        return False



def send_multi_format_email(template_prefix, template_ctxt, target_email):
    subject_file = 'erecommend/%s_subject.txt' % template_prefix
    txt_file = 'erecommend/%s.txt' % template_prefix
    html_file = 'erecommend/%s.html' % template_prefix

    subject = render_to_string(subject_file).strip()
    from_email = settings.EMAIL_FROM
    to = target_email
    bcc_email = settings.EMAIL_BCC
    text_content = render_to_string(txt_file, template_ctxt)
    html_content = render_to_string(html_file, template_ctxt)
    msg = EmailMultiAlternatives(subject, text_content, from_email, [to], bcc=[bcc_email])
    msg.attach_alternative(html_content, 'text/html')
    msg.send()
