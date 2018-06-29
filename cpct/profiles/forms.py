from django import forms


class UploadFileForm(forms.Form):
    file = forms.FileField()
    profile = forms.CharField()
    type = forms.CharField()
    version = forms.CharField()
