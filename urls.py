# Store/Urls.py

from django.urls import path
from django.contrib.auth import views as my_auth_view
from Oliasia.forms import *
from .views import *

urlpatterns = [
    path('', Index, name='home'),
    path('store-products/', ProductsView, name='products'),
    path('category/<catg_slug>/', CategoriesView, name='categories'),
    path('sub-category/<subcatg_slug>/', SubcategoriesView, name='subcategories'),
    path('brand/<brnd_slug>/', BrandsView, name='brands'),
    path('product/<prod_slug>/', ProductView, name='product'),
    path('search-products/', SearchView, name='searchproducts'),
    path('product-list/', ProductList, name="productlist"),
    path('cart/<int:user_id>', CartView, name='cart'),
    path('supercart/', SuperCartView, name='supercart'),
    path('add-to-cart/', AddToCart, name='addtocart'),
    path('delete-cart-item/', DeleteCartItem, name='deletecartitem'),
    path('update-cart/', UpdateCart, name='updatecart'),
    path("clear-cart/", ClearCart, name="clearcart"),
    path('check-out/<int:user_id>', CheckOut, name='checkout'),
    
    path('neftrtgs/payments/', NeftRtgsPayment, name='paymentsneftrtgs'), # send payment by NEFT/RTGS
    
    # Phonepay payment urls
    path('phonepe/request/', PhonepayRequest, name='phoneperequest'), # send payment request to billdesk
    path('phonepe/return/', PhonepeReturn, name='phonepereturn'),  # return response url
    path('phonepe/s2sresp/', PhonepeCallback, name='phonepes2sresp'),   # webhook url not to be change
        
    #path('payment/NeftRtgs/', NeftRtgsPayment, name='paymentneftrtgs'), # payment page
    path('billdesk/payments/', Billdesk_Payment_Request, name='billdeskpayments'), # send payment request to billdesk
    path('billdesk/handleresp/', Billdesk_Handle_Response, name='billdeskredirect'),  # return response url
    path('billdesk/s2sresp/', Billdesk_Server_To_Server, name='billdesks2s'),   # webhook url not to be change
        
    path('place-order/', PlaceOrder, name='placeorder'),
    path('buy-now/', BuyNow, name='buynow'),
    path('check-pincode/', AjaxCheckPincode, name='ajaxcheckpincode'),
    path('check-gstno/', AjaxCheckGstNo, name='ajaxcheckgstno'),
    path('add-to-wishlist/', AddToWishList, name='addtowishlist'),
    path('Clear-Wish-List/', ClearWishList, name="clearwishlist"),
    path('remove-wishlist-item/', DeleteWishListItem, name='deletewishlistitem'),
    path('show-wishlist/', ShowWishList, name='showwishlist'),
    path('my-orders/<int:user_id>', MyOrder, name='myorders'),
    path('view-order/<str:order_no>', ViewOrder, name='vieworder'),
    path('order-action/', OrderAction, name='orderaction'),
    path('contact-us/', ContactView, name='contactus'),
    path('about-us/', AboutView, name='aboutus'),
    path('terms-conditions/', TermsConditions, name='termsconditions'),
    path('privacy-policy/', PrivacyPolicy, name='privacypolicy'),
    path('shipping-delivery/', ShippingDelivery, name='shippingdelivery'),
    path('return-policy/', ReturnGoodsPolicy, name='returngoodspolicy'),
    path('cancellation-policy/', CancellationPolicy, name='cancellationpolicy'),
    path('submit-message/', SendMessage, name='submitmessage'),
    path('profile/<int:user_id>', ProfileView, name='profileview'),
    path('users-messages/<int:userid>', UsersMessages, name='usersmessages'),
    path('users-list/', UsersList, name='userslist'),
    
    path('user/registration/', Registration.as_view(), name='registration'),
    path('user/signup/', my_auth_view.LoginView.as_view(template_name='auth/login.html',
        authentication_form=UserLoginForm), name='userlogin'),
    path('logout/', LogoutView, name='userlogout'),
    path('password_change/',my_auth_view.PasswordChangeView.as_view(template_name='auth/password_change.html', 
        form_class=MyPasswordChangeForm, success_url='/password_change_done/'), name='password_change'),
    path('password_change_done/',my_auth_view.PasswordChangeView.as_view(template_name='auth/password_change_done.html', 
        form_class=MyPasswordChangeForm), name='password_change_done'),
    path('password-reset/', my_auth_view.PasswordResetView.as_view(template_name='auth/password_reset.html', 
        form_class=MyPasswordResetForm), name='password_reset'),
    path('password-reset/done/', my_auth_view.PasswordResetDoneView.as_view(template_name='auth/password_reset_done.html'), 
         name='password_reset_done'),
    path('password-reset-confirm/<uidb64>/<token>/', my_auth_view.PasswordResetConfirmView.as_view(template_name='auth/password_reset_confirm.html', 
        form_class=MySetPasswordForm), name='password_reset_confirm'),
    path('password-reset-complete/', my_auth_view.PasswordResetCompleteView.as_view(template_name='auth/password_reset_complete.html'), 
         name='password_reset_complete'),
]
