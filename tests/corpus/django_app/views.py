"""Django corpus: every rule has a *_vulnerable case and a *_safe case."""
import os
import uuid
from pathlib import Path
from urllib.request import urlopen

import jwt
import requests
from django.contrib.auth.decorators import login_required
from django.db import connection
from django.db.models.expressions import RawSQL
from django.http import FileResponse, HttpResponse, HttpResponseRedirect
from django.shortcuts import get_object_or_404, redirect, render
from django.utils.html import escape
from django.utils.http import url_has_allowed_host_and_scheme
from django.utils.safestring import mark_safe
from django.utils.text import get_valid_filename
from django.views.decorators.csrf import csrf_exempt
from rest_framework import generics, serializers, viewsets
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response

from .models import Invoice

BASE = Path("/srv/app/uploads")
SERVICES = {"billing": "https://billing.internal.example/api", "mail": "https://mail.example/api"}
ALLOWED_HOSTS_OUT = {"api.example.com", "cdn.example.com"}
JWT_KEY = os.environ["JWT_KEY"]


# --- DJ001 csrf_exempt -----------------------------------------------------

@csrf_exempt
def dj001_vulnerable_transfer(request):
    return HttpResponse("ok")


def dj001_safe_transfer(request):
    return HttpResponse("ok")


# --- DJ002 SSRF ------------------------------------------------------------

def dj002_vulnerable_requests(request):
    url = request.GET["url"]
    return HttpResponse(requests.get(url, timeout=5).status_code)


def dj002_vulnerable_urlopen(request):
    target = "https://" + request.POST.get("host", "") + "/status"
    return HttpResponse(urlopen(target).status)


def dj002_safe_fixed_service(request):
    url = SERVICES[request.GET["service"]]
    return HttpResponse(requests.get(url, timeout=5).status_code)


def dj002_safe_allowlisted_host(request):
    host = request.GET["host"]
    if host not in ALLOWED_HOSTS_OUT:
        return HttpResponse(status=400)
    return HttpResponse(requests.get(f"https://{host}/status", timeout=5).status_code)


# --- DJ003 open redirect ---------------------------------------------------

def dj003_vulnerable_redirect(request):
    return redirect(request.GET.get("next", "/"))


def dj003_vulnerable_response_redirect(request):
    target = request.POST["next"]
    return HttpResponseRedirect(target)


def dj003_safe_guarded_redirect(request):
    target = request.GET.get("next", "/")
    if not url_has_allowed_host_and_scheme(target, allowed_hosts={request.get_host()}):
        target = "/"
    return redirect(target)


def dj003_safe_guarded_branch(request):
    target = request.GET.get("next", "/")
    if url_has_allowed_host_and_scheme(target, allowed_hosts={request.get_host()}):
        return redirect(target)
    return redirect("/")


# --- DJ004 path traversal --------------------------------------------------

def dj004_vulnerable_open(request):
    name = request.GET["file"]
    return FileResponse(open(BASE / name, "rb"))


def dj004_vulnerable_path(request):
    path = Path(os.path.join("/srv/app/uploads", request.GET["file"]))
    return HttpResponse(path.name, content_type="text/plain")


def dj004_safe_basename(request):
    name = request.GET["file"]
    return FileResponse(open(BASE / os.path.basename(name), "rb"))


def dj004_safe_valid_filename(request):
    name = get_valid_filename(request.GET["file"])
    return FileResponse(open(BASE / name, "rb"))


# --- DJ005 reflected XSS ---------------------------------------------------

def dj005_vulnerable_response(request):
    name = request.GET.get("name", "")
    return HttpResponse(f"<h1>Hello {name}</h1>")


def dj005_vulnerable_mark_safe(request):
    banner = mark_safe("<b>%s</b>" % request.GET["banner"])
    return render(request, "banner.html", {"banner": banner})


def dj005_safe_escaped(request):
    name = escape(request.GET.get("name", ""))
    return HttpResponse(f"<h1>Hello {name}</h1>")


def dj005_safe_template(request):
    return render(request, "hello.html", {"name": request.GET.get("name", "")})


# --- DJ006 raw SQL ---------------------------------------------------------

def dj006_vulnerable_execute(request):
    q = request.GET["q"]
    with connection.cursor() as cursor:
        cursor.execute("SELECT id FROM billing_invoice WHERE number = '" + q + "'")
        return HttpResponse(cursor.fetchone())


def dj006_vulnerable_raw(request):
    status = request.GET["status"]
    rows = Invoice.objects.raw(f"SELECT * FROM billing_invoice WHERE status = '{status}'")
    return render(request, "invoices.html", {"rows": rows})


def dj006_vulnerable_extra(request):
    rows = Invoice.objects.extra(where=["status = '%s'" % request.GET["status"]])
    return render(request, "invoices.html", {"rows": rows})


def dj006_vulnerable_rawsql(request):
    rows = Invoice.objects.annotate(rank=RawSQL("SELECT " + request.GET["col"], []))
    return render(request, "invoices.html", {"rows": rows})


def dj006_safe_parameters(request):
    q = request.GET["q"]
    with connection.cursor() as cursor:
        cursor.execute("SELECT id FROM billing_invoice WHERE id = %s", [q])
        return HttpResponse(cursor.fetchone())


def dj006_safe_int_page(request):
    page = int(request.GET["page"])
    rows = Invoice.objects.raw(f"SELECT * FROM billing_invoice LIMIT 20 OFFSET {page * 20}")
    return render(request, "invoices.html", {"rows": rows})


# --- DJ007 JWT -------------------------------------------------------------

def dj007_vulnerable_no_signature(request):
    claims = jwt.decode(request.COOKIES["token"], options={"verify_signature": False})
    return HttpResponse(claims["sub"], content_type="text/plain")


def dj007_vulnerable_none_algorithm(request):
    claims = jwt.decode(request.COOKIES["token"], JWT_KEY, algorithms=["HS256", "none"])
    return HttpResponse(claims["sub"], content_type="text/plain")


def dj007_safe_verified(request):
    claims = jwt.decode(request.COOKIES["token"], JWT_KEY, algorithms=["HS256"])
    return HttpResponse(claims["sub"], content_type="text/plain")


# --- DJ008 AllowAny on write views -----------------------------------------

class InvoiceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Invoice
        fields = ["id", "number", "total"]


class DJ008VulnerableViewSet(viewsets.ModelViewSet):
    queryset = Invoice.objects.all()
    serializer_class = InvoiceSerializer
    permission_classes = [AllowAny]


@api_view(["POST"])
@permission_classes([AllowAny])
def dj008_vulnerable_create(request):
    return Response(status=201)


class DJ008SafeViewSet(viewsets.ModelViewSet):
    queryset = Invoice.objects.all()
    serializer_class = InvoiceSerializer
    permission_classes = [IsAuthenticated]


class DJ008SafeReadOnlyList(generics.ListAPIView):
    queryset = Invoice.objects.all()
    serializer_class = InvoiceSerializer
    permission_classes = [AllowAny]


# --- DJ009 serializer fields -----------------------------------------------

class DJ009VulnerableSerializer(serializers.ModelSerializer):
    class Meta:
        model = Invoice
        fields = "__all__"


class DJ009SafeSerializer(serializers.ModelSerializer):
    class Meta:
        model = Invoice
        fields = ["id", "number", "total"]
        read_only_fields = ["id"]


# --- DJ010 possible IDOR ---------------------------------------------------

@login_required
def dj010_vulnerable_detail(request, pk):
    invoice = Invoice.objects.get(pk=pk)
    return render(request, "invoice.html", {"invoice": invoice})


@login_required
def dj010_vulnerable_shortcut(request, invoice_id):
    invoice = get_object_or_404(Invoice, id=invoice_id)
    return render(request, "invoice.html", {"invoice": invoice})


@login_required
def dj010_safe_owner_lookup(request, pk):
    invoice = get_object_or_404(Invoice, pk=pk, owner=request.user)
    return render(request, "invoice.html", {"invoice": invoice})


@login_required
def dj010_safe_owner_check(request, pk):
    invoice = Invoice.objects.get(pk=pk)
    if invoice.owner != request.user:
        return HttpResponse(status=403)
    return render(request, "invoice.html", {"invoice": invoice})


def dj010_safe_uuid_token(request):
    token = uuid.UUID(request.GET["token"])
    invoice = get_object_or_404(Invoice, share_token=token)
    return render(request, "invoice.html", {"invoice": invoice})
