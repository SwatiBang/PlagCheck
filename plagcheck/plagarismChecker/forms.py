from django.contrib.auth.forms import UserChangeForm
from plagarismChecker.models import *
from django.utils.translation import ugettext_lazy as _
from django.core.exceptions import ValidationError
from django import forms
from django.forms import widgets, BaseFormSet
from crispy_forms.helper import FormHelper
from django.db.models import Count
from django.db.utils import ProgrammingError

from django.contrib.auth.admin import UserAdmin
from django.contrib.auth.forms import ReadOnlyPasswordHashField


class RegistrationForm(forms.Form):
    """
    Gives user form of signup and validates it.
    """
    full_name = forms.CharField(required=True, max_length=30, label=_("Full name"))
    username = forms.RegexField(regex=r'^\w+$', widget=forms.TextInput(attrs=dict(required=True, max_length=30)),
                                label=_("Username"),
                                error_messages={ 'invalid': _("This value must contain only letters, "
                                                              "numbers and underscores.") })
    email = forms.EmailField(widget=forms.TextInput(attrs=dict(required=True, max_length=30)), label=_("Email address"))
    password1 = forms.CharField(widget=forms.PasswordInput(attrs=dict(required=True, max_length=30,
                                                                      render_value=False)), label=_("Password"))
    password2 = forms.CharField(widget=forms.PasswordInput(attrs=dict(required=True, max_length=30,
                                                                      render_value=False)), label=_("Password (again)"))


    def clean_username(self):
        """
        Validates username.
        """
        try:
            user = User.objects.get(username__iexact=self.cleaned_data['username'])
        except User.DoesNotExist:
            return self.cleaned_data['username']
        raise forms.ValidationError(_("The username already exists. Please try another one."))

    def clean(self):
        """
        Validates the values inserted in Password and Confirm Password field are same.
        """
        if 'password1' in self.cleaned_data and 'password2' in self.cleaned_data:
            if self.cleaned_data['password1'] != self.cleaned_data['password2']:
                raise forms.ValidationError(_("The two password fields did not match."))

def validatefiletype(file):
    """
    Validates type of uploaded file.

    Parameters
    ----------
    file : file
        The file that is uploaded.

    Raises
    ------
    ValidationError
        Raises this exception if uploaded file is neither plain text nor PDF
    """
    # TODO: add PDF back in once we have a better system in place for processing
    #  large uploads.
    if file.content_type != 'text/plain' and  file.content_type != 'application/pdf':
        raise ValidationError('ERROR: Please choose a plain text file.')


class UploadTestForm(forms.Form):
    filetoupload = forms.FileField(label='Choose a plain text file:',
                required=True,
                validators=[validatefiletype],
                help_text="Upload files with .txt, .rb, .c, .cpp, .html, .rtf, .css, .pdf, .docx")
    filetoupload1 = forms.FileField(label='Choose a plain text file:',
                required=True,
                validators=[validatefiletype],
                help_text="Upload files with .txt, .rb, .c, .cpp, .html, .rtf, .css, .pdf, .docx")



class UploadFileForm(forms.Form):
    title = forms.CharField(max_length=255, required=True,
                            help_text='The title of the original resource.')
    filetoupload = forms.FileField(label='Choose a plain text file:',
                required=True,
                validators=[validatefiletype],
                help_text="Upload files with .txt, .rb, .c, .cpp, .html, .rtf, .css")

class UserCreationForm(forms.ModelForm):

    password1 = forms.CharField(label='Password', widget=forms.PasswordInput)
    password2 = forms.CharField(label='Password confirmation', widget=forms.PasswordInput)

    class Meta:
        model = User
        fields = ('full_name', 'email')

    def clean_password2(self):
        # Check that the two password entries match
        password1 = self.cleaned_data.get("password1")
        password2 = self.cleaned_data.get("password2")
        if password1 and password2 and password1 != password2:
            raise forms.ValidationError("Passwords don't match")
        return password2

    def save(self, commit=True):
        # Save the provided password in hashed format
        user = super(UserCreationForm, self).save(commit=False)
        user.set_password(self.cleaned_data["password1"])
        if commit:
            user.save()
        return user


class UserChangeForm(forms.ModelForm):

    class Meta:
        model = User
        fields = ('full_name', 'email')

    def clean_password(self):
        # Regardless of what the user provides, return the initial value.
        # This is done here, rather than on the field, because the
        # field does not have access to the initial value
        return self.initial.get("password")
