from django.shortcuts import render, redirect
from fpkilint.html_output import *
from django.http import HttpResponse, JsonResponse, HttpResponseRedirect
from .forms import UploadFileForm
import json
import os
module_dir = os.path.dirname(__file__)  # get current directory


def dashboard(request):
    file_path = os.path.join(module_dir, 'profiles.json')
    with open(file_path) as f:
        profiles = f.read()

    form = UploadFileForm()

    return render(request, 'upload.html', {'form': form, 'profiles': profiles})


def upload_file(request):
    file_path = os.path.join(module_dir, 'profiles.json')
    with open(file_path) as f:
        profiles = f.read()

    if request.method == 'POST':
        form = UploadFileForm(request.POST, request.FILES)
        if form.is_valid():
            file = request.FILES['file']
            try:
                cert = parse_certificate(file.read())
            except:
                return HttpResponse(
                    "<div class='callout callout-danger' style=border-radius:5px;>File could not be parsed</div>")

            profile = int(form.cleaned_data['profile'])
            type = int(form.cleaned_data['type'])
            version = int(form.cleaned_data['version'])
            data = json.loads(profiles)

            try:
                template = data['profiles'][profile]['versions'][version]['cert_types'][type]['template']
            except:
                return HttpResponse("<div class='callout callout-danger' style=border-radius:5px;>Invalid Template</div>")

            # rows, type, string, url, short_name = analyze_certificate(cert, template)

            try:
                rows, type, string, url, short_name = analyze_certificate(cert, template)
            except:
                return HttpResponse(
                    "<div class='callout callout-danger' style=border-radius:5px;>Unrecoverable Error</div>")

            return render(request, 'result.html', {'rows': rows, 'type': type, 'string': string, 'url': url,
                                                   'short_name': short_name})
        else:
            return HttpResponse("<div class='callout callout-danger' style=border-radius:5px;>You must select a profile.</div>")
    else:
        return HttpResponse("<div class='callout callout-danger' style=border-radius:5px;>Invalid Request (not POST)</div>")


def help(request):
    return render(request, 'help.html')

def privacy(request):
    return render(request, 'privacy-policy.html')

def contact(request):
    return render(request, 'contact-us.html')
