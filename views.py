# ********   VIEWS.PY *********
from .views import *
from .models import *
from Oliasia.forms import *

from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required
from django.contrib import auth, messages
from django.shortcuts import render, redirect
from django.views import View
from django.http import JsonResponse, HttpResponse, HttpResponseRedirect
from django.db.models import Sum
from django.conf import settings
from django.core.mail import send_mass_mail
from datetime import datetime
from django.db.models import Max
from django_billdesk import ResponseMessage, GetMessage
from django.db.models import Q
from django.core.paginator import Paginator, PageNotAnInteger, EmptyPage
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

import json as myjson
import base64
import requests
import shortuuid
import uuid
import math
import jwt
import hashlib
import hmac
import logging
import re

# Global variables *************************************************
order_status_filter = ['Confirmed','Packed']
pre_url = "/"
superuser = User.objects.filter(is_superuser=True).first()
cart = shipping_charge = actual_weight = applied_weight = shipping_weight = zonal_rate = applied_rate = cart_amt = order_value = total_items_in_cart = wishlist = orders = 0.00
total_items_in_cart = 0
transporter = profile = ""
PRODUCTS_PER_PAGE = 30
last_query = ""

logger = logging.getLogger('store')

# Phonepe functions
def generate_tran_id():
    uuid_part = str(uuid.uuid4()).split('-')[0].upper()
    now = datetime.now().strftime('%Ym%d')
    return f"TRX{now}{uuid_part}"
def generate_checksum(data, salt_key, salt_index):
    checksum_str = data + '/pg/v1/pay' + salt_key
    checksum = hashlib.sha256(checksum_str.encode()).hexdigest() + '###' + salt_index
    return checksum

@csrf_exempt
def PhonepayRequest(request):
    order_value = 0.00
    new_order_no = user_phone = ""
    profile = Profile.objects.filter(user=request.user.id).first()
    if request.method == "POST":
        order_value = int(float(request.POST.get('amount-phonepe')))
        dict_max_odr = Order.objects.aggregate(Max('id'))
        max_odr_no = dict_max_odr["id__max"]
        if max_odr_no is not None:
            max_odr_no = int(max_odr_no) + 1
        else:
            max_odr_no = 1
        new_order_no = str(1000+request.user.id)+str(datetime.now().year)+str(max_odr_no).zfill(5)

    PAYMENT_URL = settings.PHONEPE_TEST_URL
    MERCHANT_ID = settings.PHONEPE_TEST_MID
    SALT_KEY = settings.PHONEPE_TEST_SALT_KEY
    SALT_INDEX = "1"
    ENDPOINT = "/pg/v1/pay"
    
    payload = {
        "merchantId": MERCHANT_ID,
        "merchantTransactionId": generate_tran_id(),
        "merchantUserId": new_order_no,
        "amount": 100, # order_value*100,  # in paisa
        "redirectUrl": "/phonepe/return/",
        "redirectMode": "POST",
        "callbackUrl": "/phonepe/s2sresp/",
        "mobileNumber": profile.phone,
        "paymentInstrument": {
            "type": "PAY_PAGE"
        }
    }
   
    data = base64.b64encode(myjson.dumps(payload).encode()).decode()
    checksum = generate_checksum(data, SALT_KEY, SALT_INDEX)
    final_payload = {
        'request': data,
    }
    headers = {
        'content-type': 'application/json',
        'X-VERIFY': checksum,
        'accept': 'application/json',        
    }
    
    try:
        response = requests.post(PAYMENT_URL+ENDPOINT, headers=headers, json=final_payload)
        data = response.json()
        logger.info(data)
        if data['success']:
            url = data['data']['instrumentResponse']['redirectInfo']['url']
            return redirect(url)
        else:
            return redirect('phoneperequest')
        
    except Exception as e:
        logger.info("initiate payment:: %s", e)
        return redirect('phoneperequest')

@csrf_exempt
def PhonepeReturn(request):
    form_data = request.POST
    form_data_dict = dict(form_data)
    transection_id = form_data.get('transactionId', None)
    if transection_id:
        request_url = settings.PHONEPE_URL+settings.PHONEPE_ENDPOINT_STATUS+'/'+settings.PHONEPE_MID+'/'+transection_id
        sha256_Pay_load_String = settings.PHONEPE_ENDPOINT_STATUS+'/'+settings.PHONEPE_MID+'/'+transection_id+settings.PHONEPE_SALT_KEY
        sha256_val = calculate_sha256_string(sha256_Pay_load_String)
        checksum = sha256_val+"###"+settings.PHONEPE_INDEX
    headers = {
        'content-type': 'application/json',
        'X-VERIFY': checksum,
        'X-MERCHANT-ID': transection_id,
        'accept': 'application/json',
    }
    response = requests.get(request_url, headers=headers)
    return render(request, 'index.html', { 'output':response.text, 'main_request':form_data_dict })
    
@csrf_exempt
def PhonepeCallback(request):
    if request.method != "POST":
        logger.error("Invalid request method: %s", request.method)
        return redirect('phonepereturn')
    try:
        data = request.POST.dict() # convert QueryDict to a regular dictionary
        logger.info(data)
        if data.get('checksum') and data.get('code') == "PAYMENT_SUCCESS":
            response = render(request, 'cart/phonepe-payment-success.html')
            return response
        else:
            logger.info("After payment report:: %s", data)
            return render(request,'cart/phonepe-payment-failed.html')
    except Exception as e:
        logger.error("Error passing rtequest body:: %s", e)
        render(request, 'cart/phonepe-payment-failed.html')

        
# Billdesk functions
def get_order_id(id):
    return str(id)+str(uuid.uuid4())[:8]
def calculate_sha256_string(input_string):
    sha256 = hashes.Hash(hashes.SHA256(), backend=default_backend())
    sha256.update(input_string.encode('utf-8'))
    return sha256.finalize().hex()
def base64_encode(input_dict):
    json_data = myjson.dumps(input_dict)
    data_bytes = json_data.encode('utf-8')
    return base64.b64encode(data_bytes).decode('utf-8')

def Billdesk_Payment_Request(request):
    if request.method == 'GET':
        fname = request.user.first_name
        email_id = request.user.email
        profile = Profile.objects.filter(user=request.user.id).first()
        mnumber = profile.phone
        # get new unique order id
        dict_max_odr = Order.objects.aggregate(Max('id'))
        max_odr_no = dict_max_odr["id__max"]
        if max_odr_no is not None:
            max_odr_no = int(max_odr_no) + 1
        else:
            max_odr_no = 1  # if no order found
        new_order_no = str(1000+request.user.id)+str(datetime.now().year)+str(max_odr_no).zfill(5)
        
    headers = {
        "alg":"HS256",
        "clientid":settings.BILLDESK_CLNT_ID
    }
    payload = {
        "mercid":settings.BILLDESK_MID,
        "orderid":get_order_id(request.user.id),
        "amount":"100.00",
        "order_date":"2023-07-16T10:59:15+05:30",
        "currency":"356",
        "ru":"/billdesk/handleresp/",
        "additional_info":{
            "additional_info1":fname,
            "additional_info3":mnumber
        },
        "itemcode":"DIRECT",
        "device":{
            "init_channel":"internet",
            "ip":"195.35.21.146",
            "accept_header":"text/html",
            "user_agent":"Windows 10",
        }
    }
    encoded_header = jwt.encode(headers, settings.BILLDESK_SEC_KEY, algorithm="HS256")
    encoded_payload = jwt.encode(payload, settings.BILLDESK_SEC_KEY, algorithm="HS256")
    encoded_private_key = str.encode(settings.BILLDESK_SEC_KEY)
    
    signature = hmac.new(encoded_private_key, encoded_header+'.'+encoded_payload, hashlib.sha256)
    tokan = signature.hexdigest()
    auth_tokan = encoded_header + '.' + encoded_payload + '.' + tokan
    
    context ={
        'mercid':settings.BILLDESK_MID,
        'auth_tokan':auth_tokan,
        'new_order_no':new_order_no,
        'oid':get_order_id(request.user.id),
    }
    return JsonResponse(context)

@csrf_exempt
def Billdesk_Handle_Response(request):
    if request.method=='POST':
        response = request.POST
        values = ResponseMessage.respMsg(response)
        if values is not False and values['BILLDESK_MID']==settings.BILLDESK_MID:
            transac = Transaction.objects.filter(order_id=values['OrderID'])[0]
            tstat,amnt,txnid,dnt,mode = values['TStat'],values['AMNT'], values['TaxnNo'],values['DnT'],values['TMode']
            if tstat == '0300' and transac.amount_initiated==float(amnt):
                    id = transac.owner.id
                    reg_for = eval(transac.registered_for)
                    profile = Profile.objects.filter(id=id)[0]
                    # usr_details = Spectator.objects.filter(id=id)[0]
                    typ = 'success'
                    msgs = ['Success','Payment Succesful', reg_for]
            elif tstat == '0300' and transac.amount_initiated!=amnt:
                reg_for = eval(transac.registered_for)
                #transac.status = 'AMOUNT Tampered'
                #transac.was_success = False
                msgs = ['Failed', 'Payment declined! Looked liked someone tried tampering your payment',reg_for]
                typ='danger'
            elif tstat == '0002':
                reg_for = eval(transac.registered_for)
                msgs = ['Failed', 'Billdesk is waiting for the trasaction status from your bank. Will update you as soon as we have any response',reg_for]
                typ = 'info'
            elif tstat != '0300':
                if tstat == '0399':
                    detail = 'Invalid Authentication at Bank'
                elif tstat == 'NA':
                    detail = 'Invalid Input in the Request Message'
                elif tstat =='0001':
                    detail = 'error at billdesk'
                else:
                    detail = 'Payment Failed'
                #transac.status = "FAILED"
                reg_for = eval(transac.registered_for)
                msgs = ['Failed', detail, reg_for]
                typ = 'danger'
                transac.log += str([response])
                transac.ru_date = timezone.localtime(timezone.now())
                transac.save()
                return render(request, 'cart/billdesk-after-payment.html', {'error': msgs, 'typ':typ, 'txnid':txnid, 'date':dnt, 'amnt': amnt, 'mode':mode})
            else:
                return HttpResponse('Bad Request')
        else:
            msgs = ['Failed','Payment declined! Looked liked someone tried tampering your payment']
            return render(request, 'cart/billdesk-after-payment.html', {'error': msgs, 'typ': 'danger'})
    else:
        return HttpResponse('Bad Request')

@csrf_exempt
def Billdesk_Server_To_Server(request):
    pass

def AjaxCheckPincode(request):
    if request.method == 'POST':
        context={
            'status':'0',
            'msg':"Invalid pincode ... please try again",
            'district' : '', 
            'division' : '',
            'region' : '',
            'block' : '',
            'state' : '',
        } 
        pincode = request.POST.get("pincode")
        
        response = request.get(settings.PINCODE_ENDPOINT+pincode)
        pincode_info = myjson.loads(response.text)
        required_pincode_info = pincode_info[0]['PostOffice'][0]
        if required_pincode_info:
            context={
                'district' : required_pincode_info["District"], 
                'division' : required_pincode_info["Division"],
                'region' : required_pincode_info["Region"],
                'block' : required_pincode_info["Block"],
                'state' : required_pincode_info["State"],
            }
            if required_pincode_info["DeliveryStatus"] == "Delivery":
                context['status'] = '1',
                context['msg'] = "Product will be delivered in 5-7 working days.",
            else:
                context['status'] = '0',
                context['msg'] = "Service not available...",
        
        return JsonResponse(context)
    return redirect('/store-products')

def AjaxCheckGstNo(request):
    # Set the API endpoint and headers
    headers = {
        'client_id': settings.GST_CLIENT_ID,
        'client_secret': settings.GST_CLIENT_SECRET,
        'Content-Type': 'application/json'
    }

    # Set the request parameters
    data = {
        'emai': 'nenobaimpexco@gmail.com',
        'gstin': '27ACQPC6742D1ZM'
    }

    # Send the request
    response = requests.get(settings.GST_ENDPOINT, headers=headers, data=data)
    # Parse the response
    response_data = myjson.loads(response.text)
    
    gstin = response_data['gstin']
    return HttpResponse('Bad Request')
   
def Index(request):
    total_items_in_cart = wishlist = orders = 0
    if request.user.is_authenticated:
        if request.user.is_superuser:
            total_items_in_cart = Cart.objects.all().count()
            wishlist = Wishlist.objects.all()
            orders = Order.objects.filter(order_status__in=order_status_filter)
        else:
            total_items_in_cart = Cart.objects.filter(user=request.user).aggregate(Sum('quantity')).get('quantity__sum')
            wishlist = Wishlist.objects.filter(user=request.user)
            orders = Order.objects.filter(user=request.user, order_status__in=order_status_filter)
    allcategories = Category.objects.all()
    allsubcategories = Subcategory.objects.all()
    carts = Cart.objects.all()
    order_items = OrderItem.objects.all()
    context={
        'allcategories':allcategories,
        'allsubcategories':allsubcategories,
        'carts':carts,
        'total_items_in_cart':total_items_in_cart,
        'wishlist':wishlist,
        'orders':orders,
        'order_items':order_items,
    }
    return render(request, 'index.html',context)

def CategoriesView(request, catg_slug):
    allcategories = Category.objects.all().order_by("name")
    allproducts = products =  Product.objects.filter(web_status="Publish")
    allbrands = Brand.objects.all().order_by("name")
    total_items_in_cart = wishlist = orders = 0
    if request.user.is_authenticated:
        if request.user.is_superuser:
            total_items_in_cart = Cart.objects.all().count()
            wishlist = Wishlist.objects.all()
            orders = Order.objects.filter(order_status__in=order_status_filter)
        else:
            total_items_in_cart = Cart.objects.filter(user=request.user).aggregate(Sum('quantity')).get('quantity__sum')
            wishlist = Wishlist.objects.filter(user=request.user)
            orders = Order.objects.filter(user=request.user, order_status__in=order_status_filter)
    obj_catg = Category.objects.filter(slug=catg_slug).first()
    products = Product.objects.filter(web_status="Publish", subcategory__category__slug=catg_slug).order_by('subcategory').order_by('catalog')
    paginator = Paginator(products, 30, orphans=1)
    page_number = request.GET.get('page')
    page_object = paginator.get_page(page_number)
    context={
        'allcategories':allcategories,
        'allproducts':allproducts,
        'allbrands':allbrands,
        'products':products,
        'obj_catg':obj_catg,
        'page_object':page_object,
        'total_items_in_cart':total_items_in_cart,
        'wishlist':wishlist,
        'orders':orders,
        'pagetitle':obj_catg.name,
    }
    return render(request, 'products.html', context)

def SubcategoriesView(request, subcatg_slug):
    allcategories = Category.objects.all().order_by("name")
    allproducts = products =  Product.objects.filter(web_status="Publish")
    allbrands = Brand.objects.all().order_by("name")
    total_items_in_cart = wishlist = orders = 0
    if request.user.is_authenticated:
        if request.user.is_superuser:
            total_items_in_cart = Cart.objects.all().count()
            wishlist = Wishlist.objects.all()
            orders = Order.objects.filter(order_status__in=order_status_filter)
        else:
            total_items_in_cart = Cart.objects.filter(user=request.user).aggregate(Sum('quantity')).get('quantity__sum')
            wishlist = Wishlist.objects.filter(user=request.user)
            orders = Order.objects.filter(user=request.user, order_status__in=order_status_filter)
    obj_subcatg = Subcategory.objects.filter(slug=subcatg_slug).first()
    products = Product.objects.filter(web_status="Publish", subcategory__slug=subcatg_slug).order_by('subcategory').order_by('catalog')
    paginator = Paginator(products, 30, orphans=1)
    page_number = request.GET.get('page')
    page_object = paginator.get_page(page_number)
    context={
        'allcategories':allcategories,
        'allproducts':allproducts,
        'allbrands':allbrands,
        'products':products,
        'obj_subcatg':obj_subcatg,
        'page_object':page_object,
        'total_items_in_cart':total_items_in_cart,
        'wishlist':wishlist,
        'orders':orders,
        'pagetitle':obj_subcatg.name,
    }
    return render(request, 'products.html', context)

def BrandsView(request, brnd_slug):
    allcategories = Category.objects.all().order_by("name")
    allproducts = products =  Product.objects.filter(web_status="Publish")
    allbrands = Brand.objects.all().order_by("name")
    total_items_in_cart = wishlist = orders = 0
    if request.user.is_authenticated:
        if request.user.is_superuser:
            total_items_in_cart = Cart.objects.all().count()
            wishlist = Wishlist.objects.all()
            orders = Order.objects.filter(order_status__in=order_status_filter)
        else:
            total_items_in_cart = Cart.objects.filter(user=request.user).aggregate(Sum('quantity')).get('quantity__sum')
            wishlist = Wishlist.objects.filter(user=request.user)
            orders = Order.objects.filter(user=request.user, order_status__in=order_status_filter)
    obj_brnd = Brand.objects.filter(slug=brnd_slug).first()
    products = Product.objects.filter(web_status="Publish", brand__slug=brnd_slug).order_by('subcategory').order_by('catalog')
    paginator = Paginator(products, 30, orphans=1)
    page_number = request.GET.get('page')
    page_object = paginator.get_page(page_number)
    context={
        'allcategories':allcategories,
        'allproducts':allproducts,
        'allbrands':allbrands,
        'products':products,
        'obj_brnd':obj_brnd,
        'page_object':page_object,
        'total_items_in_cart':total_items_in_cart,
        'wishlist':wishlist,
        'orders':orders,
        'pagetitle':obj_brnd.name+' Products',
    }
    return render(request, 'products.html', context)

def ProductsView(request):
    allcategories = Category.objects.all().order_by("name")
    allproducts = products =  Product.objects.filter(web_status="Publish")
    allbrands = Brand.objects.all().order_by("name")
    total_items_in_cart = wishlist = orders = 0
    if request.user.is_authenticated:
        if request.user.is_superuser:
            total_items_in_cart = Cart.objects.all().count()
            wishlist = Wishlist.objects.all()
            orders = Order.objects.filter(order_status__in=order_status_filter)
        else:
            total_items_in_cart = Cart.objects.filter(user=request.user).aggregate(Sum('quantity')).get('quantity__sum')
            wishlist = Wishlist.objects.filter(user=request.user)
            orders = Order.objects.filter(user=request.user, order_status__in=order_status_filter)
    products = Product.objects.filter(web_status="Publish").order_by('brand')
    paginator = Paginator(products, 30, orphans=1)
    page_number = request.GET.get('page')
    page_object = paginator.get_page(page_number)
    context={
        'allcategories':allcategories,
        'allproducts':allproducts,
        'allbrands':allbrands,
        'products':products,
        'page_object':page_object,
        'total_items_in_cart':total_items_in_cart,
        'wishlist':wishlist,
        'orders':orders,
        'pagetitle':'Irrigation Products and Hardware Items',
    }
    return render(request, 'products.html', context)

def SearchView(request):
    global last_query
    allcategories = Category.objects.all().order_by("name")
    allproducts = Product.objects.filter(web_status="Publish")
    allbrands = Brand.objects.all().order_by("name")
    total_items_in_cart = wishlist = orders = 0
    if request.user.is_authenticated:
        if request.user.is_superuser:
            total_items_in_cart = Cart.objects.all().count()
            wishlist = Wishlist.objects.all()
            orders = Order.objects.filter(order_status__in=order_status_filter)
        else:
            total_items_in_cart = Cart.objects.filter(user=request.user).aggregate(Sum('quantity')).get('quantity__sum')
            wishlist = Wishlist.objects.filter(user=request.user)
            orders = Order.objects.filter(user=request.user, order_status__in=order_status_filter)
    query = request.POST.get("search-text")
    if query:
        last_query = query
    else:
        query = last_query
    query = re.sub('-',' ',query)
    query_list = re.sub(r'(\d+(\.\d+)?)', r' \1 ', query).split() # Create a list items from search text
    q_objects = Q() # Create an empty Q object to start with
    for word in query_list:
        q_objects &= Q(name__contains=word)
    products = Product.objects.filter(q_objects).order_by('catalog')
    page = request.GET.get('page',1)
    paginator = Paginator(products, PRODUCTS_PER_PAGE, orphans=1)
    page_object = paginator.get_page(page)
    context = {
        'total_items_in_cart':total_items_in_cart,
        'wishlist':wishlist,
        'orders':orders,
        'allcategories':allcategories,
        'allproducts':allproducts,
        'allbrands':allbrands,
        'products':products,
        'page_object':page_object,
        'query':query,
        'pagetitle':'Irrigation Products and Hardware Items',
    }
    return render(request, 'products.html', context)

def ProductView(request, prod_slug):
    total_items_in_cart = wishlist = orders = 0
    if request.user.is_authenticated:
        profile = Profile.objects.filter(user=request.user).first()
        if request.user.is_superuser:
            total_items_in_cart = Cart.objects.all().count()
            wishlist = Wishlist.objects.all()
            orders = Order.objects.filter(order_status__in=order_status_filter)
        else:
            total_items_in_cart = Cart.objects.filter(user=request.user).aggregate(Sum('quantity')).get('quantity__sum')
            wishlist = Wishlist.objects.filter(user=request.user)
            orders = Order.objects.filter(user=request.user, order_status__in=order_status_filter)
    else:
        profile = ""
    allcategories = Category.objects.all().order_by("name")
    product = Product.objects.filter(slug=prod_slug).first()
    technical = Technical.objects.filter(product__slug=prod_slug)
    tds = TDS.objects.filter(product__slug=prod_slug)
    reviews = Review.objects.filter(product__slug=prod_slug)
    context={
        'total_items_in_cart':total_items_in_cart, 
        'wishlist':wishlist,
        'allcategories':allcategories,
        'product':product,
        'technical':technical,
        'tds':tds,
        'reviews':reviews,
        'orders':orders,
        'profile':profile,
        }
    return render(request, 'product-detail.html',context)        

def AddToCart(request):
    if request.method == 'POST':
        if request.user.is_authenticated:    
            pid = request.POST.get('pid')
            qty = int(request.POST.get('qty'))
            product = Product.objects.get(id=pid)
            if(product):
                if(Cart.objects.filter(user=request.user, product=pid)):  # if product already in cart
                    return JsonResponse({'status':'Product already in cart...'})    
                else:
                    if(qty <= product.stock):
                        Cart.objects.create(
                            user=request.user, 
                            product=product, 
                            quantity=qty, 
                            items_amount = float(qty)*product.net_price
                        )
                        cart_count = Cart.objects.filter(user=request.user).aggregate(Sum('quantity')).get('quantity__sum')
                        if request.user.is_superuser:
                            total_items_in_cart = Cart.objects.all().count()
                        else:
                            total_items_in_cart = Cart.objects.filter(user=request.user).aggregate(Sum('quantity')).get('quantity__sum')
                        return JsonResponse({'status':'Product added in cart !!!','cart_count': cart_count,})
                    else:
                        return JsonResponse({'status':'Only '+str(product.stock)+' quantity available...'})
            else:   
                 return JsonResponse({'status':'No such product found...'})
        else:
            return JsonResponse({'status':'Please login to continue...'})
    return redirect('/store-products')

@login_required
def BuyNow(request):
    if request.method == "POST":
        pid = request.POST.get("product-id")
        qty = request.POST.get("input-qty-"+pid)
        product = Product.objects.filter(id=pid).first()
        if product: # if product exists
            if not (Cart.objects.filter(user=request.user, product=pid)):
                if(int(qty) <= product.stock):
                    Cart.objects.create(user=request.user, product=product, quantity=qty, items_amount=float(qty)*product.net_price)
    return redirect('cart', user_id = request.user.id)

def SuperCartView(request):
    wishlist = orders = 0
    users = User.objects.all().order_by('-last_login')
    carts = Cart.objects.all().order_by('-id')
    orders = Order.objects.filter(order_status__in=order_status_filter)
    wishlist = Wishlist.objects.all()
    context={
        'users':users,
        'carts':carts,
        'total_items_in_cart':carts.count(),
        'wishlist':wishlist,
        'orders':orders,
    }
    return render(request,'cart/super-cart.html',context)
    
def CartView(request, user_id):
    total_items_in_cart = wishlist = orders = 0
    cart_owner = User.objects.filter(id=user_id).first()
    if  request.user.is_authenticated:
        total_items_in_cart = Cart.objects.filter(user=user_id).aggregate(Sum('quantity')).get('quantity__sum')
        if request.user.is_superuser:
            wishlist = Wishlist.objects.all()
            orders = Order.objects.filter(order_status__in=order_status_filter)
        else:
            wishlist = Wishlist.objects.filter(user=request.user)
            orders = Order.objects.filter(user=request.user, order_status__in=order_status_filter)
    update_cart_values(request, user_id)
    context={
        'cart_owner':cart_owner,
        'cart':cart,
        'shipping_charge':shipping_charge,
        'cart_amt':cart_amt,
        'order_value':order_value,
        'total_items_in_cart':total_items_in_cart,
        'wishlist':wishlist,
        'orders':orders,
        'zonal_rate':zonal_rate,
        'actual_weight':actual_weight,
        'applied_weight':applied_weight,
        'shipping_weight':shipping_weight,
        'applied_rate':applied_rate,
    }
    return render(request,'cart/cart.html',context)

def UpdateCart(request):
    if request.method == 'POST':
        order_user = request.POST.get("order_user")
        prod_id = request.POST.get("product_id")
        prod_qty = request.POST.get('product_qty')
        if Cart.objects.get(user=order_user, product=prod_id):
            # Update cart quantity
            cart = Cart.objects.get(user=order_user, product=prod_id)
            cart.quantity = prod_qty
            cart.items_amount = float(prod_qty)*cart.product.net_price
            if request.user.id == int(order_user):
                cart.save()
            # Recalculate cart amount
        update_cart_values(request, order_user)
        cart_count = Cart.objects.filter(user=request.user).aggregate(Sum('quantity')).get('quantity__sum')
        context = {
            'status':'Cart updated successfully  !!!',
            'cart_count': cart_count,
        }
        return JsonResponse(context)
    else:
        return JsonResponse({'status':'not updated...'})

def DeleteCartItem(request):
    if request.method == 'POST':
        item_id = request.POST.get('item_id')
        if(Cart.objects.filter(user=request.user, id=item_id)):
            cartitem = Cart.objects.get(user=request.user, id=item_id)
            cartitem.delete()
            cart_count = Cart.objects.filter(user=request.user).aggregate(Sum('quantity')).get('quantity__sum')
            context = {
                'status':'Item removed successfully...',
                'cart_count':cart_count,
            }
            return JsonResponse(context)
        else:
            return JsonResponse({'status':'Product not available in cart...'})
    return redirect('/')

def ShowWishList(request):
    total_items_in_cart = wishlist = orders = 0
    if request.user.is_authenticated:
        if request.user.is_superuser:
            total_items_in_cart = Cart.objects.all().count()
            wishlist = Wishlist.objects.all()
            orders = Order.objects.filter(order_status__in=order_status_filter)
        else:
            total_items_in_cart = Cart.objects.filter(user=request.user).aggregate(Sum('quantity')).get('quantity__sum')
            wishlist = Wishlist.objects.filter(user=request.user)
            orders = Order.objects.filter(user=request.user, order_status__in=order_status_filter)
    context={
        'total_items_in_cart':total_items_in_cart,
        'wishlist':wishlist,
        'orders':orders,
    }
    return render(request, 'cart/wishlist.html',context)

def DeleteWishListItem(request):
    if request.method == 'POST':
        if request.user.is_authenticated:
            prod_id = int(request.POST.get('product_id'))
            if(Wishlist.objects.filter(user=request.user, product=prod_id)):
                wishlist_item = Wishlist.objects.get(product=prod_id, user=request.user)
                wishlist_item.delete()
                return JsonResponse({'status':'Product removed from wishlist...'})
            else:
                return JsonResponse({'status':'Product not found in wishlist...'})
        else:
            return JsonResponse({'status':'Login to continue...'})
    return redirect('/')

def AddToWishList(request):
    if request.method == 'POST':
        if request.user.is_authenticated:    
            pid = int(request.POST.get('pid'))
            product = Product.objects.get(id=pid)
            if(product):
                if(Wishlist.objects.filter(user=request.user, product=pid)):
                    return JsonResponse({'status':'Product already in wishlist...'})    
                else:
                    Wishlist.objects.create(user=request.user, product=product)
                    return JsonResponse({'status':'Product added in wishlist !!!'})
            else:   
                 return JsonResponse({'status':'No such product found...'})
        else:
            return JsonResponse({'status':'Please login to continue...'})
    return redirect('/store-products')

def CheckOut(request, user_id):
    if request.user.is_authenticated:
        if request.user.is_superuser:
            total_items_in_cart = Cart.objects.all().count()
            wishlist = Wishlist.objects.all()
            orders = Order.objects.filter(order_status__in=order_status_filter)
        else:
            total_items_in_cart = Cart.objects.filter(user=request.user).aggregate(Sum('quantity')).get('quantity__sum')
            wishlist = Wishlist.objects.filter(user=request.user)
            orders = Order.objects.filter(user=request.user, order_status__in=order_status_filter)
    usr_profile = Profile.objects.filter(user=request.user).first()
    if (not usr_profile or not request.user.first_name) or (not usr_profile.state_name or not usr_profile.country):
        return redirect('profileview', user_id=request.user.id) # if user profile incomplete
    rawcart = Cart.objects.filter(user=user_id)
    # Delete items in cart if out-of-stock
    for item in rawcart:
        if item.quantity > item.product.stock:
            Cart.objects.filter(user=user_id,id=item.id).delete()
    update_cart_values(request, user_id)
    cart_owner = User.objects.filter(id=user_id).first()
    context={
        'cart_owner':cart_owner,
        'cart':cart,
        'shipping_charge':shipping_charge,
        'order_value':order_value,
        'actual_weight':actual_weight,
        'total_items_in_cart':total_items_in_cart,
        'wishlist':wishlist,
        'orders':orders,
        'profile':profile,
        'transporter':transporter,
    }
    return render(request,'cart/check-out.html', context)

def RazorpayPayment(request):
    # calculate amount
    userprofile = Profile.objects.filter(user=request.user).first()
    cartitems = Cart.objects.filter(user=request.user)
    order_value = total_weight = 0.00
    for item in cartitems:
        order_value += item.product.net_price*item.quantity
        total_weight += item.product.item_weight*item.quantity
    order_value = round(order_value,0)
    data = {
        'total_weight':total_weight,
        'order_value':order_value,
        'razorpay_key_id':settings.RAZORPAY_KEY_ID,
        'fname':request.user.first_name,
        'lname':request.user.last_name,
        'email':request.user.email,
        'phone':userprofile.phone,
        'address':userprofile.address,
        'message':request.GET.get("message"),
        'status':'Razorpay payment request accepted...',
    }
    return JsonResponse(data)

def PlaceOrder(request):
    global superuser
    pay_ref_no = order_note = pay_date = new_order_no = ""
    order_value = 0.00
    if request.method == "POST":
        new_order_no = request.POST.get("order-no") 
        order_weight = request.POST.get("order-weight")
        order_value = request.POST.get("order-value")
        shipping_charge = request.POST.get("shipping-charge")
        pay_ref_no = request.POST.get("utr-no")
        pay_mode = "Pending"
        if pay_ref_no:
            pay_mode = 'Prepaid'
        order_note = request.POST.get("order-note")
        userprofile = Profile.objects.filter(user=request.user).first()
        if new_order_no: # if new order placed
            payment_id = request.POST.get("utr-no")
            error_message = ""
            created = Order.objects.update_or_create(
                order_no = new_order_no,
                defaults={'payment_id':payment_id, 'error_message':error_message},
            )
        else:    # if order modified
            dict_max_odr = Order.objects.aggregate(Max('id'))
            max_odr_no = dict_max_odr["id__max"]
            if max_odr_no is not None:
                max_odr_no = int(max_odr_no) + 1
            else:
                max_odr_no = 1
            new_order_no = str(1000+request.user.id)+str(datetime.now().year)+str(max_odr_no).zfill(5)
            neworder = Order(
                user = request.user, 
                order_no = new_order_no,
                order_weight = order_weight,
                shipping_charges = shipping_charge,
                order_value = float(order_value),
                fname = request.user.first_name,
                lname = request.user.last_name,
                email = request.user.email,
                phone = userprofile.phone,
                address = userprofile.address,
                country = userprofile.country,
                state_name = userprofile.state_name,
                city = userprofile.city,
                pincode = userprofile.pincode,
                gst_no =  userprofile.gst_no,
                payment_id = pay_ref_no,
                payment_mode = pay_mode,
                error_message = "",
                message = order_note,
            )
            neworder.save()
            # add OrderItems
            neworderitems = Cart.objects.filter(user=request.user)
            for item in neworderitems:
                OrderItem.objects.create(
                    order = neworder,
                    product = item.product,
                    price = item.product.net_price,
                    quantity = item.quantity
                )
                # Update stock in Product table for each items
                orderproduct = Product.objects.filter(id=item.product.id).first()
                orderproduct.stock = orderproduct.stock-item.quantity
                orderproduct.save()
            # remove discount from profile on shipping charge
            updated = Profile.objects.update_or_create(
                user=request.user,
                defaults={'discount_on_shipping':0.00},
            )
            # Clear the cart
            Cart.objects.filter(user=request.user).delete()
        if request.user.is_superuser:
            total_items_in_cart = Cart.objects.all().count()
            wishlist = Wishlist.objects.all()
            orders = Order.objects.filter(order_status__in=order_status_filter)
        else:
            total_items_in_cart = Cart.objects.filter(user=request.user).aggregate(Sum('quantity')).get('quantity__sum')
            wishlist = Wishlist.objects.filter(user=request.user)
            orders = Order.objects.filter(user=request.user, order_status__in=order_status_filter)
        order = Order.objects.filter(order_no = new_order_no).first()
        context={
            'order':order,
            'order_value':order_value,
            'new_order_no':new_order_no,
            'pay_ref_no':pay_ref_no,
            'pay_date':pay_date,
            'order_note':order_note,
            'total_items_in_cart':total_items_in_cart,
            'wishlist':wishlist,
            'orders':orders,
        }
        message1 = (
            "www.oliasia.in: Order #" + new_order_no,
            "Dear " + request.user.first_name + ' ' + request.user.last_name + ", Your order #:" + new_order_no + " has been placed succefully... Thank you for using www.oliasia.in",
            settings.EMAIL_HOST_USER,
            [request.user.email],
        )
        message2 = (
            "Congratulations !!! new order received on www.oliasia.in",
            "Dear "+ superuser.username +", You have receiced a new order #" + new_order_no + " on www.oliasia.in",
            settings.EMAIL_HOST_USER,
            [superuser.email],
        )
        send_mass_mail((message1, message2), fail_silently=False)
        return render(request,"cart/order-placed.html", context)
    return redirect('/')

def ClearCart(request):
    cart = Cart.objects.filter(user=request.user)
    cart.delete()
    return HttpResponseRedirect(request.META.get('HTTP_REFERER'))

def ClearWishList(request):
    wishlist = Wishlist.objects.filter(user=request.user)
    wishlist.delete()
    return HttpResponseRedirect(request.META.get('HTTP_REFERER'))

def ProfileView(request, user_id):
    global pre_url
    objuser = User.objects.filter(id=user_id).first()
    context = orders = ""
    total_items_in_cart = Cart.objects.filter(user=request.user).aggregate(Sum('quantity')).get('quantity__sum')
    allcategories = Category.objects.all().order_by("name")
    wishlist = Wishlist.objects.filter(user=request.user)
    if request.user.is_superuser:
        total_items_in_cart = Cart.objects.all().count()
        wishlist = Wishlist.objects.all()
        orders = Order.objects.filter(order_status__in=order_status_filter)
    else:
        total_items_in_cart = Cart.objects.filter(user=request.user).aggregate(Sum('quantity')).get('quantity__sum')
        wishlist = Wishlist.objects.filter(user=request.user)
        orders = Order.objects.filter(user=request.user, order_status__in=order_status_filter)
    countries = Country.objects.all().order_by('name')
    states = State.objects.all().order_by('name')
    profile = Profile.objects.filter(user=user_id).first()
    if request.method == "GET":  
        pre_url = request.META.get('HTTP_REFERER')
    if request.method == "POST": 
        if request.user:
            currentuser = request.user
            currentuser.first_name = request.POST.get('fname')
            currentuser.last_name = request.POST.get('lname')
            currentuser.save()
        if not profile:
            profile = Profile()
        profile.user = request.user
        profile.address = request.POST.get('address')
        profile.phone = request.POST.get('phone')
        profile.country = Country.objects.filter(id=request.POST.get('country')).first()
        profile.pincode = request.POST.get('input-pincode')
        profile.city = request.POST.get('city')
        profile.district = request.POST.get('district')
        profile.state_name = State.objects.filter(id=request.POST.get('state-name')).first()
        profile.gst_no = request.POST.get('gst-no')
        profile.save()
        return redirect(pre_url)
    context={
        'objuser':objuser,
        'allcategories':allcategories,
        'profile_user':user_id,
        'profile':profile,
        'total_items_in_cart':total_items_in_cart,
        'wishlist':wishlist,
        'orders':orders,
        'states':states,
        'countries':countries,
    }
    return render(request,'auth/profile.html', context)

def UsersList(request):
    context={}
    if request.user.is_authenticated and request.user.is_superuser:
        total_items_in_cart = Cart.objects.all().count()
        wishlist = Wishlist.objects.all()
        orders = Order.objects.filter(order_status__in=order_status_filter)
        users = User.objects.all().order_by('-last_login')
        profiles = Profile.objects.all()
        messages = Message.objects.all()
        today = datetime.now()
        context={
            'total_items_in_cart':total_items_in_cart,
            'wishlist':wishlist,
            'orders':orders,
            'users':users,
            'profiles':profiles,
            'messages':messages,
            'today':today,
        }
    return render(request,'auth/users_list.html',context)

def UsersMessages(request, userid):
    context={}
    if request.user.is_authenticated and request.user.is_superuser:
        total_items_in_cart = Cart.objects.all().count()
        wishlist = Wishlist.objects.all()
        orders = Order.objects.filter(order_status__in=order_status_filter)
        usermessages = Message.objects.filter(user=userid)
        objuser = User.objects.filter(id=userid).first()
        context={
            'usermessages':usermessages,
            'total_items_in_cart':total_items_in_cart,
            'wishlist':wishlist,
            'orders':orders,
            'objuser':objuser,
        }
    return render(request,'auth/users_messages.html',context)

def ProductList(request):
    products = Product.objects.all().values_list('name', flat=True)
    productslist = list(products)
    return JsonResponse(productslist, safe=False)

def LogoutView(request):
    auth.logout(request)
    return redirect('/')

def MyOrder(request, user_id):
    total_items_in_cart = wishlist = orders = 0
    total_order_value=pending_order_value=packed_order_value=delivered_order_value=canceled_order_value=return_request_order_value=returned_order_value=0.00
    if request.user.is_authenticated:
        if request.user.is_superuser:
            total_items_in_cart = Cart.objects.all().count()
            wishlist = Wishlist.objects.all()
            orders = Order.objects.filter(order_status__in=order_status_filter)
            all_orders = Order.objects.all().order_by("-id")
            total_order_value = all_orders.aggregate(Sum('order_value'))
            orders_pending = Order.objects.filter(order_status='Confirmed').order_by("-id")
            pending_order_value = orders_pending.aggregate(Sum('order_value'))
            orders_packed = Order.objects.filter(order_status='Packed').order_by("-id")
            packed_order_value = orders_packed.aggregate(Sum('order_value'))
            orders_shipped = Order.objects.filter(order_status='Shipped').order_by("-id")
            shipped_order_value = orders_shipped.aggregate(Sum('order_value'))
            orders_delivered = Order.objects.filter(order_status='Delivered').order_by("-id")
            delivered_order_value = orders_delivered.aggregate(Sum('order_value'))
            orders_cancelled = Order.objects.filter(order_status='Cancelled').order_by("-id")
            canceled_order_value = orders_cancelled.aggregate(Sum('order_value'))
            orders_return_requested = Order.objects.filter(order_status='Return Request').order_by("-id")
            return_request_order_value = orders_return_requested.aggregate(Sum('order_value'))
            orders_returned = Order.objects.filter(order_status='Returned').order_by("-id")
            returned_order_value = orders_returned.aggregate(Sum('order_value'))
            context={
                'user_id':user_id,
                'orders':orders,
                'all_orders':all_orders,
                'orders_pending':orders_pending,
                'orders_packed':orders_packed,
                'orders_shipped':orders_shipped,
                'orders_delivered':orders_delivered,
                'orders_cancelled':orders_cancelled,
                'orders_return_requested':orders_return_requested,
                'orders_returned':orders_returned,
                'total_items_in_cart':total_items_in_cart,
                'wishlist':wishlist,
                'total_order_value':total_order_value,
                'pending_order_value':pending_order_value,
                'packed_order_value':packed_order_value,
                'shipped_order_value':shipped_order_value,
                'delivered_order_value':delivered_order_value,
                'canceled_order_value':canceled_order_value,
                'return_request_order_value':return_request_order_value,
                'returned_order_value':returned_order_value,
            }
        else:
            orders = Order.objects.filter(user=user_id, order_status__in=order_status_filter)
            all_orders = Order.objects.filter(user=user_id).order_by('-id')
            total_items_in_cart = Cart.objects.filter(user=request.user).aggregate(Sum('quantity')).get('quantity__sum')
            wishlist = Wishlist.objects.filter(user=request.user).order_by('-id')
            total_order_value = Order.objects.filter(user=user_id).aggregate(Sum('order_value'))
            context={
                'user_id':user_id,
                'orders':orders,
                'all_orders':all_orders,
                'total_order_value':total_order_value,
                'total_items_in_cart':total_items_in_cart,
                'wishlist':wishlist,
            }
    if request.user.is_superuser:
        return render(request, 'store/orders/orders.html', context)
    else:
        return render(request, 'store/orders/myorders.html', context)
    
def ViewOrder(request, order_no):
    total_items_in_cart = orders = wishlist = 0
    if request.user.is_authenticated:
        if request.user.is_superuser:
            total_items_in_cart = Cart.objects.all().count()
            wishlist = Wishlist.objects.all()
            orders = Order.objects.filter(order_status__in=order_status_filter)
        else:
            total_items_in_cart = Cart.objects.filter(user=request.user).aggregate(Sum('quantity')).get('quantity__sum')
            wishlist = Wishlist.objects.filter(user=request.user)
            orders = Order.objects.filter(user=request.user, order_status__in=order_status_filter)
    allcategories = Category.objects.all().order_by("name")
    order = Order.objects.filter(order_no=order_no).first()
    orderitems = OrderItem.objects.filter(order=order)
    context={
        'order_no':order_no,
        'allcategories':allcategories,
        'order':order,
        'orders':orders,
        'orderitems':orderitems,
        'total_items_in_cart':total_items_in_cart,
        'wishlist':wishlist,
    }
    return render(request,'store/orders/vieworder.html', context)

def OrderAction(request):
    if request.method == 'POST':
        current_order = Order.objects.get(id=request.POST.get('order-id')) 
        order_value = request.POST.get('oder_value')
        order_items = OrderItem.objects.filter(order=current_order)
        # If Order Cancelled
        if ('order-id' in request.POST and 'cancel-order' in request.POST):
            # Re-stock for the cancelled items
            for item in order_items:
                product = Product.objects.get(id=item.product.id)
                product.stock += item.quantity
                product.save()
            current_order.order_status="Cancelled"
            current_order.save()
        # If Return Request sent
        elif ('order-id' in request.POST and 'return-request' in request.POST):
            current_order.order_status = "Return Request"
            current_order.save()
    return redirect('myorders', user_id=request.user.id)

def TermsConditions(request):
    allcategories = Category.objects.all().order_by("name")
    company = Company.objects.all().first()
    context = {
        "company":company,
        'allcategories':allcategories,
    }
    return render(request, 'policy-terms-conditions.html', context)

def PrivacyPolicy(request):
    allcategories = Category.objects.all().order_by("name")
    company = Company.objects.all().first()
    context = {
        "company":company,
        'allcategories':allcategories,
    }
    return render(request, 'policy-privacy.html', context)

def ShippingDelivery(request):
    allcategories = Category.objects.all().order_by("name")
    company = Company.objects.all().first()
    context = {
        "company":company,
        'allcategories':allcategories,
    }
    return render(request, 'policy-shipping-delivery.html', context)

def ReturnGoodsPolicy(request):
    allcategories = Category.objects.all().order_by("name")
    company = Company.objects.all().first()
    context = {
        "company":company,
        'allcategories':allcategories,
    }
    return render(request, 'policy-return.html', context)

def CancellationPolicy(request):
    allcategories = Category.objects.all().order_by("name")
    company = Company.objects.all().first()
    context = {
        "company":company,
        'allcategories':allcategories,
    }
    return render(request, 'policy-cancellation.html', context)

def SendMessage(request):
    if request.user.is_authenticated:    
        if request.method == 'POST':
            user_name = request.POST['user_name']
            user_email = request.POST['user_email']
            user_phone = request.POST['user_phone']
            user_subject = request.POST['user_subject']
            user_message = request.POST['user_message']
            new_message = Message(
                user=request.user,
                name=user_name, 
                email=user_email,
                phone=user_phone,
                subject=user_subject,
                message=user_message,)
            new_message.save()
            return JsonResponse({
                'status':'Your message submitted successfully...',
                'error':'',
                })
    else:
        return JsonResponse({
            'status':'', 
            'error':'Error: Please login to continue...',
            })

def AboutView(request):
    total_items_in_cart = wishlist = orders = 0
    if request.user.is_authenticated:
        if request.user.is_superuser:
            total_items_in_cart = Cart.objects.all().count()
            wishlist = Wishlist.objects.all()
            orders = Order.objects.filter(order_status__in=order_status_filter)
        else:
            total_items_in_cart = Cart.objects.filter(user=request.user).aggregate(Sum('quantity')).get('quantity__sum')
            wishlist = Wishlist.objects.filter(user=request.user)
            orders = Order.objects.filter(user=request.user, order_status__in=order_status_filter)
    allcategories = Category.objects.all().order_by("name")
    company = Company.objects.filter().first
    context={
        'allcategories':allcategories,
        'total_items_in_cart': total_items_in_cart,
        'wishlist':wishlist,
        'company':company,
        'orders':orders,
    }
    return render(request,'about-us.html',context)

def ContactView(request):
    total_items_in_cart = wishlist = orders = 0
    if request.user.is_authenticated:
        if request.user.is_superuser:
            total_items_in_cart = Cart.objects.all().count()
            wishlist = Wishlist.objects.all()
            orders = Order.objects.filter(order_status__in=order_status_filter)
        else:
            total_items_in_cart = Cart.objects.filter(user=request.user).aggregate(Sum('quantity')).get('quantity__sum')
            wishlist = Wishlist.objects.filter(user=request.user)
            orders = Order.objects.filter(user=request.user, order_status__in=order_status_filter)
    allcategories = Category.objects.all().order_by("name")
    company = Company.objects.filter().first
    profile = Profile.objects.filter(user=request.user.id).first()
    context={
        'allcategories':allcategories,
        'total_items_in_cart': total_items_in_cart,
        'wishlist':wishlist,
        'orders':orders,
        'company':company,
        'profile':profile,
    }
    return render(request,'contact-us.html',context)

def NeftRtgsPayment(request):
    if request.user.is_superuser:
        total_items_in_cart = Cart.objects.all().count()
        wishlist = Wishlist.objects.all()
        orders = Order.objects.filter(order_status__in=order_status_filter)
    else:
        total_items_in_cart = Cart.objects.filter(user=request.user).aggregate(Sum('quantity')).get('quantity__sum')
        wishlist = Wishlist.objects.filter(user=request.user)
        orders = Order.objects.filter(user=request.user, order_status__in=order_status_filter)
    bill_amount = 0
    order_no = order_note = ""
    if request.method == "POST":
        order_no = request.POST.get('order-no')
        order_weight = request.POST.get('order-weight')
        shipping_charge = request.POST.get('neftrtgs-shipping-charges')
        bill_amount = request.POST.get('amount-neftrtgs')
        order_note =  request.POST.get('neftrtgs-message')
    context={
        'order_no':order_no,
        'order_weight':order_weight,
        'bill_amount':bill_amount,
        'shipping_charge':shipping_charge,
        'order_note':order_note,
        'total_items_in_cart':total_items_in_cart,
        'wishlist':wishlist,
        'orders':orders,
    }
    return render(request, 'cart/neftrtgs-payment-process.html', context)

def update_cart_values(request, user_id):
    global cart, transporter, shipping_charge, actual_weight, applied_weight, shipping_weight, zonal_rate, applied_rate, cart_amt, order_value, total_items_in_cart, wishlist, orders, profile
    if request.user.is_superuser:
        total_items_in_cart = Cart.objects.all().count()
        wishlist = Wishlist.objects.all()
        orders = Order.objects.filter(order_status__in=order_status_filter)
    else:
        total_items_in_cart = Cart.objects.filter(user=request.user).aggregate(Sum('quantity')).get('quantity__sum')
        wishlist = Wishlist.objects.filter(user=request.user)
        orders = Order.objects.filter(user=request.user, order_status__in=order_status_filter)
    # define variables
    profile = Profile.objects.filter(user=user_id).first()
    if profile:
        if profile.country:
            country_id = profile.country
        else:
            country_id = 1 # Set default country        
    else:
        country_id = 1 # Set default country
    transporter = ""
    cart_amt = shipping_charge = order_value = actual_weight = order_volume = zonal_rate = 0.00
    shipping_weight = 0.5
    packing_weight = 10  # value in %
    courier = "Xpressbees"
    shipping_mode = "surface_courier"
    shipping_type = "forward"
    user_zone = '3'
    if profile and profile.state_name:
        user_zone = profile.state_name.shipping_zone
    # calculate weight and volume
    cart = Cart.objects.filter(user=user_id)
    for item in cart:
        order_volume += (item.product.item_length*item.product.item_height*item.product.item_width) * (item.quantity)
        actual_weight += item.product.item_weight * item.quantity
        cart_amt += item.quantity*item.product.net_price
    # add packing weight
    applied_weight += (packing_weight/100)*actual_weight
    # round off
    applied_weight = math.ceil(actual_weight)
    # Set shipping weight range
    if actual_weight <= 0.5:
        shipping_weight = 1
    elif 0.5 < actual_weight <= 1:
        shipping_weight = 1
    elif 1 < actual_weight <= 2:
        shipping_weight = 2
    elif 2 < actual_weight <= 3:
        shipping_weight = 3
    elif 3 < actual_weight <= 5:
        shipping_weight = 5
    elif 5 < actual_weight <= 10:
        shipping_weight = 10
    elif 10 < actual_weight:
        shipping_weight = 20
    
    # get Transporter detail
    transporter = Transporter.objects.get(
        courier_name = courier,
        country = country_id, 
        ship_mode = shipping_mode,
        ship_type = shipping_type,
        ship_weight = shipping_weight,
        )
    applied_rate = 95
    if user_zone == 1:
        zonal_rate = transporter.zone_1       
        applied_rate = 59
    elif user_zone == 2:
        zonal_rate = transporter.zone_2            
        applied_rate = 65
    elif user_zone == 3:
        zonal_rate = transporter.zone_3
        applied_rate = 75
    elif user_zone == 4:
        zonal_rate = transporter.zone_4            
        applied_rate = 85
    elif user_zone == 5:
        zonal_rate = transporter.zone_5          
        applied_rate = 95
    # applied_rate = zonal_rate
    
    # apply value discount
    # if 999 < cart_amt <= 2000:
    #      applied_rate = applied_rate - ((10/100)*applied_rate)
    # elif 2000 < cart_amt <= 5000:
    #      applied_rate = applied_rate - ((20/100)*applied_rate)
    # elif cart_amt > 5000:
    #      applied_rate = applied_rate - ((20/100)*applied_rate)

    shipping_charge = round(applied_weight*applied_rate)
    
    # apply additional discount 
    if profile:
        shipping_charge = shipping_charge - profile.discount_on_shipping
    
    order_value = cart_amt + shipping_charge
    return order_value, shipping_charge

class Registration(View):
    def get(self, request):
        form = UserRegistrationForm()    
        context = {'form':form}
        return render(request,'auth/register.html',context)
    def post(self, request):
        form = UserRegistrationForm(request.POST)
        if form.is_valid():
            messages.success(request, 'Congratulations !! User registered sucessfully.')
            form.save()
            return redirect('userlogin')
        return render(request,'auth/register.html',{'form':form})     
