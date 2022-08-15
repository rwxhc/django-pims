import json

from django.shortcuts import render
from django.http.response import HttpResponse, JsonResponse
from django.http.response import HttpResponseRedirect
from django.http import Http404
from django.shortcuts import redirect
from django.urls import reverse
from django.views.decorators.csrf import csrf_exempt
from django.contrib import messages
from django.contrib.auth import logout
from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from django.core.paginator import Paginator

# 表单快捷函数
from .forms import fsf_get_new_password_form
from .forms import fsf_get_post_password_form
from .forms import fsf_get_data_form
from .forms import fsf_get_post_data_form

from .forms import UserRegistryForm
from .forms import ModifyLoginPasswordForm

# 密码模型快捷函数
from .models import msf_get_password_model
from .models import msf_get_new_password_model

from .models import msf_password_is_set
from .models import msf_password_is_valid
from .models import msf_recover_password_is_set

from .models import msf_change_recover_password
from .models import msf_change_password

from .models import msf_save_password_model
from .models import msf_save_recover_password_model

# 数据模型快捷函数
from .models import msf_get_data_model_list
from .models import msf_get_data_model
from .models import msf_get_new_data_model
from .models import msf_save_data_model

# 工具函数
from .utils import uf_hash, uf_encrypt, uf_decrypt

def vf_logout(request):
    user_name = request.user.username
    logout(request)
    response = redirect('/login/')
    response.delete_cookie(user_name)
    return response

def vf_registry(request):
    if request.method == 'GET':
        obj_form_registry = UserRegistryForm()
        context = {"form": obj_form_registry}
        return render(request, 'private_info/registry.html', context=context)
    elif request.method == 'POST':
        obj_form_registry = UserRegistryForm(request.POST)
        if obj_form_registry.is_valid():
            username = obj_form_registry.cleaned_data["username"]
            password = obj_form_registry.cleaned_data["password"]
            try:
                User.objects.create_user(username=username, password=password)
            except Exception as e:
                messages.error(request, "注册失败：{}".format(str(e)))
                context = {"form": obj_form_registry}
                return render(request, 'private_info/registry.html', context=context)
            messages.success(request, "注册用户成功！")
            return redirect("/login")
        else:
            messages.error(request, "表单有误")
            context = {"form": obj_form_registry}
            return render(request, 'private_info/registry.html', context=context)
    else:
        return Http404("不支持的方法")


def vf_login_password_modify(request):
    if request.method == 'GET':
        obj_form = ModifyLoginPasswordForm()
        context = {"form": obj_form}
        return render(request, 'private_info/chpass.html', context=context)
    elif request.method == 'POST':
        obj_form = ModifyLoginPasswordForm(request.POST)
        if obj_form.is_valid():
            old_password = obj_form.cleaned_data["old_password"]
            password = obj_form.cleaned_data["password"]
            # 验证用户密码
            v_user = authenticate(username=request.user.username, password=old_password)
            if not v_user:
                messages.error(request, "原密码不正确！")
                context = {"form": obj_form}
                return render(request, 'private_info/chpass.html', context=context)
            v_user.set_password(password)
            v_user.save()
            messages.success(request, "密码修改成功，请重新登录！")
            return redirect("/login")
        else:
            messages.error(request, "表单有误")
            context = {"form": obj_form}
            return render(request, 'private_info/chpass.html', context=context)
    else:
        return Http404("不支持的方法")


# 密码相关页面附加信息
ext_password_info = {
    "recover": {
        "new": {"title": "请设置超级密码", "desc": "超级密码是用于加密其他密码，用于其他密码遗忘时恢复。超级密码遗忘将无法恢复！！！",
                "password_type": "recover"},
        "modify": {"title": "修改超级密码", "desc": "修改超级密码将使用新密码重新加密其他密码。",
                   "password_type": "recover"},
        "get": {"title": "超级密码", "desc": "超级密码是用于加密其他密码，用于其他密码遗忘时恢复。超级密码遗忘将无法恢复！！！",
                "password_type": "recover", "allow_show":False},
    },
    "simple": {
        "new": {"title": "请设置简单密码", "desc": "简单密码是用于保护明文信息，简单密码遗忘可用超级密码找回。",
                "password_type": "simple"},
        "modify": {"title": "修改简单密码", "desc": "修改简单密码，无需旧密码，直接输入新密码。",
                   "password_type": "simple"},
        "get": {"title": "简单密码", "desc": "简单密码是用于保护明文信息，简单密码遗忘可用超级密码找回。",
                "password_type": "simple", "allow_show":True},
        "auth": {"title": "获取权限", "desc": "请输入超级密码",
                "password_type": "simple"},
        "display": {"title": "查看简单密码", "desc": "请输入超级密码来查看。",
                "password_type": "simple"},
    },
    "normal": {
        "new": {"title": "请设置普通密码", "desc": "普通密码是用于加密普通信息，普通密码遗忘可用超级密码找回。",
                "password_type": "normal"},
        "modify": {"title": "修改普通密码", "desc": "修改普通密码，无需旧密码，直接输入新密码。",
                   "password_type": "normal"},
        "get": {"title": "普通密码", "desc": "普通密码是用于加密普通信息，普通密码遗忘可用超级密码找回。",
                "password_type": "normal", "allow_show":True},
        "auth": {"title": "获取权限", "desc": "请输入超级密码",
                "password_type": "normal"},
        "display": {"title": "查看普通密码", "desc": "请输入超级密码来查看。",
                "password_type": "normal"},
    },
    "private": {
        "new": {"title": "请设置重要密码", "desc": "重要密码是用于加密重要信息，重要密码遗忘可用超级密码找回。",
                "password_type": "private"},
        "modify": {"title": "修改重要密码", "desc": "修改重要密码，无需旧密码，直接输入新密码。",
                   "password_type": "private"},
        "get": {"title": "重要密码", "desc": "重要密码是用于加密重要信息，重要密码遗忘可用超级密码找回。",
                "password_type": "private", "allow_show":True},
        "auth": {"title": "获取权限", "desc": "请输入超级密码",
                "password_type": "private"},
        "display": {"title": "查看重要密码", "desc": "请输入超级密码来查看。",
                "password_type": "private"},
    },
}

ALL_PASSWORD_TYPE_LIST = ['recover', 'simple', 'normal', 'private']
DATA_PASSWORD_TYPE_LIST = ['simple', 'normal', 'private']

# 显示密码信息
def vf_password(request, password_type):
    """
    password_type: recover 超级密码, simple 简单密码, normal 普通密码. private 重要密码
    """
    if not request.user.is_authenticated:
        return redirect('%s?next=%s' % (settings.LOGIN_URL, request.path))

    if password_type not in ALL_PASSWORD_TYPE_LIST:
        return Http404("密码类型错误：{}".format(password_type))

    # 获取当前类型密码数据
    obj_model_password = msf_get_password_model(password_type, request.user)

    if request.method == 'GET':

        # 检查超级密码
        if password_type != 'recover':
            if not msf_recover_password_is_set(request.user):
                messages.info(request, "超级密码未设置！")
                return redirect('private_info:vn-password-new', password_type='recover')

        # 检查密码是否设置
        if not obj_model_password:
            messages.info(request, "密码未设置！")
            return redirect('private_info:vn-password-new', password_type=password_type)

        # 密码已设置，显示密码
        obj_form_password = fsf_get_new_password_form(password_type, 'get')
        obj_form_password.fields["prompt"].initial = obj_model_password.prompt
        context = {"form": obj_form_password, "ext_info": ext_password_info[password_type]['get']}
        return render(request, 'private_info/main-password.html', context=context)

    else:
        return Http404("不支持的方法: {}".format(request.method))


# 添加其他密码、修改密码、查看密码需要先验证超级密码
def vf_password_auth(request, password_type, action):
    """
    action: new, modify, display
    """

    if not request.user.is_authenticated:
        return redirect('%s?next=%s' % (settings.LOGIN_URL, request.path))

    if password_type not in ALL_PASSWORD_TYPE_LIST:
        return Http404("密码类型错误：{}".format(password_type))

    if request.method == 'GET':
        obj_form_password = fsf_get_new_password_form(password_type, 'auth')
        ext_info = ext_password_info[password_type]['auth']
        ext_info['action'] = action
        context = {"form": obj_form_password, "ext_info": ext_info}
        return render(request, 'private_info/main-password-auth.html', context=context)

    elif request.method == 'POST':
        obj_form_password = fsf_get_post_password_form(password_type, 'auth', request)
        if obj_form_password.is_valid():
            # 读取超级密码
            recover_password = obj_form_password.cleaned_data['password']
            # 验证超级密码
            if not msf_password_is_valid('recover', recover_password, request.user):
                messages.warning(request, "超级密码错误！")
                ext_info = ext_password_info[password_type]['auth']
                ext_info['action'] = action
                context = {"form": obj_form_password, "ext_info": ext_info}
                return render(request, 'private_info/main-password-auth.html', context=context)

            # 超级密码验证通过，根据 action 准备页面。
            obj_form = fsf_get_new_password_form(password_type, action)
            if not obj_form:
                return Http404("不支持的操作：{}".format(action))

            if action == 'modify':
                obj_form.fields['recover_password'].initial = recover_password
                obj_model = msf_get_password_model(password_type, request.user)
                if not obj_model:
                    return Http404("查询密码数据异常！")
                obj_form.fields['prompt'].initial = obj_model.prompt
            elif action == 'new':
                obj_form.fields['recover_password'].initial = recover_password
            elif action == 'display':
                obj_model = msf_get_password_model(password_type, request.user)
                if not obj_model:
                    return Http404("查询密码数据异常！")
                obj_form.fields['prompt'].initial = obj_model.prompt
                clear_password = uf_decrypt(obj_model.encrypt_password, recover_password)
                if not clear_password:
                    return Http404("密码解密异常！")
                obj_form.fields['password'].initial = clear_password
            else:
                return Http404("不支持的操作：{}".format(action))

            ext_info = ext_password_info[password_type][action]
            context = {"form": obj_form, "ext_info": ext_info}
            if action == 'new':
                return render(request, 'private_info/main-password-new.html', context=context)
            elif action == 'modify':
                return render(request, 'private_info/main-password-modify.html', context=context)
            elif action == 'display':
                return render(request, 'private_info/main-password-display.html', context=context)

        else:  # 表单验证问题
            messages.warning(request, "输入有误，请检查表单！")
            ext_info = ext_password_info[password_type]['auth']
            ext_info['action'] = action
            context = {"form": obj_form_password, "ext_info": ext_info}
            return render(request, 'private_info/main-password-auth.html', context=context)
    else:
        return Http404("不支持的方法: {}".format(request.method))


# 添加密码
def vf_password_new(request, password_type):
    """
    password_type: recover 超级密码, simple 简单密码, normal 普通密码. private 重要密码
    """
    if not request.user.is_authenticated:
        return redirect('%s?next=%s' % (settings.LOGIN_URL, request.path))

    if password_type not in ALL_PASSWORD_TYPE_LIST:
        return Http404("密码类型错误：{}".format(password_type))

    # 获取当前类型密码数据
    obj_model_password = msf_get_password_model(password_type, request.user)
    if obj_model_password:
        messages.info(request, "密码已设置！")
        return redirect('private_info:vn-password', password_type=password_type)

    if request.method == 'GET':
        if password_type != 'recover':
            return redirect('private_info:vn-password-auth', password_type=password_type, action='new')

        # 超级密码
        obj_form_password = fsf_get_new_password_form(password_type, 'new')
        ext_info = ext_password_info[password_type]['new']
        context = {"form": obj_form_password, "ext_info": ext_info}
        return render(request, 'private_info/main-password-new.html', context=context)

    elif request.method == 'POST':
        obj_form_password = fsf_get_post_password_form(password_type, 'new', request)
        if obj_form_password.is_valid():
            # 从表单获取输入
            password = obj_form_password.cleaned_data['password']
            prompt = obj_form_password.cleaned_data['prompt']

            # 超级密码
            if password_type == 'recover':
                obj_model_password = msf_get_new_password_model(password_type)
                result = msf_save_recover_password_model(password, prompt, request.user, obj_model_password)
                if result:
                    messages.success(request, "密码设置成功！")
                else:
                    messages.error(request, "密码保存失败！")

            # 其他密码
            else:
                # 验证超级密码
                recover_password = obj_form_password.cleaned_data['recover_password']
                if not msf_password_is_valid('recover', recover_password, request.user):
                    return Http404("超级密码错误！")  # 正常操作流程不会到这

                # 保存密码
                obj_model_password = msf_get_new_password_model(password_type)
                result = msf_save_password_model(recover_password, password, prompt, request.user, obj_model_password)
                if result:
                    messages.success(request, "密码设置成功！")
                else:
                    messages.error(request, "保存密码失败！")
            return redirect('private_info:vn-password', password_type=password_type)

        else:
            messages.warning(request, "输入有误，请检查表单！")
            context = {"form": obj_form_password, "ext_info": ext_password_info[password_type]['new']}
            return render(request, 'private_info/main-password-new.html', context=context)
    else:
        return Http404("不支持的方法: {}".format(request.method))

# 修改密码
def vf_password_modify(request, password_type):
    if not request.user.is_authenticated:
        return redirect('%s?next=%s' % (settings.LOGIN_URL, request.path))

    if password_type not in ALL_PASSWORD_TYPE_LIST:
        return Http404("密码类型错误：{}".format(password_type))

    obj_model_password = msf_get_password_model(password_type, request.user)
    if not obj_model_password:
        return Http404("密码数据异常！")

    if request.method == 'GET':
        # 不是超级密码，进入验证步骤
        if password_type != 'recover':
            return redirect('private_info:vn-password-auth', password_type=password_type, action='modify')

        obj_form_password = fsf_get_new_password_form(password_type, 'modify')
        obj_form_password.fields['prompt'].initial = obj_model_password.prompt
        context = {"form": obj_form_password, "ext_info": ext_password_info[password_type]['modify']}
        return render(request, 'private_info/main-password-modify.html', context=context)

    elif request.method == 'POST':
        # 修改密码
        obj_form_password = fsf_get_post_password_form(password_type, 'modify', request)
        if obj_form_password.is_valid():
            # 从表单获取输入
            password = obj_form_password.cleaned_data['password']
            prompt = obj_form_password.cleaned_data['prompt']

            # 超级密码
            if password_type == 'recover':
                # 验证旧密码
                old_password = obj_form_password.cleaned_data['old_password']
                if not msf_password_is_valid(password_type, old_password, request.user):
                    messages.warning(request, "原密码输入错误！")
                    context = {"form": obj_form_password, "ext_info": ext_password_info[password_type]['modify']}
                    return render(request, 'private_info/main-password-modify.html', context=context)
                # 修改超级密码，并重新加密其他密码
                result, result_msg = msf_change_recover_password(old_password, password, prompt, obj_model_password)

            else:  # 其他密码
                # 验证超级密码
                recover_password = obj_form_password.cleaned_data['recover_password']
                if not msf_password_is_valid('recover', recover_password, request.user):
                    messages.warning(request, "超级密码错误！")
                    context = {"form": obj_form_password, "ext_info": ext_password_info[password_type]['modify']}
                    return render(request, 'private_info/main-password-modify.html', context=context)

                # 修改其他密码，并用新密码加密对应保护数据
                result, result_msg = msf_change_password(password_type,recover_password,password,prompt, obj_model_password)

            # 返回密码修改结果
            messages.info(request, result_msg)
            return redirect('private_info:vn-password', password_type=password_type)

        else:  # 表单验证问题
            messages.warning(request, "输入有误，请检查表单！")
            context = {"form": obj_form_password, "ext_info": ext_password_info[password_type]['modify']}
            return render(request, 'private_info/main-password-modify.html', context=context)
    else:
        return Http404("不支持的方法: {}".format(request.method))

# 查看密码
def vf_password_display(request, password_type):
    if not request.user.is_authenticated:
        return redirect('%s?next=%s' % (settings.LOGIN_URL, request.path))

    if password_type not in DATA_PASSWORD_TYPE_LIST:
        return Http404("密码类型错误：{}".format(password_type))

    obj_model_password = msf_get_password_model(password_type, request.user)
    if not obj_model_password:
        return Http404("查询密码数据异常！")

    if request.method == 'GET':
        obj_form_password = fsf_get_new_password_form(password_type, 'auth')
        context = {"form": obj_form_password, "ext_info": ext_password_info[password_type]['auth']}
        return render(request, 'private_info/main-password-auth.html', context=context)
    elif request.method == 'POST':
        # 查看密码
        obj_form_password = fsf_get_post_password_form(password_type, 'auth', request)
        if obj_form_password.is_valid():
            # 检查超级密码
            recover_password = obj_form_password.cleaned_data['password']
            if not msf_password_is_valid('recover', recover_password, request.user):
                messages.warning(request, "超级密码错误！")
                context = {"form": obj_form_password, "ext_info": ext_password_info[password_type]['auth']}
                return render(request, 'private_info/main-password-auth.html', context=context)

            # 解密密码
            clear_password = uf_decrypt(obj_model_password.encrypt_password, recover_password)
            if not clear_password:
                messages.error(request, "解密异常！")
            # 准备显示修改
            form = fsf_get_new_password_form(password_type, 'display')
            form.fields["prompt"].initial = obj_model_password.prompt
            form.fields["password"].initial = clear_password
            context = {"form": form, "ext_info": ext_password_info[password_type]['display']}
            return render(request, 'private_info/main-password-display.html', context=context)
        else:
            messages.warning(request, "输入有误，请检查表单！")
            context = {"form": obj_form_password, "ext_info": ext_password_info[password_type]['auth']}
            return render(request, 'private_info/main-password-auth.html', context=context)
    else:
        return Http404("不支持的方法")


####################################################################################################
## 信息部分视图函数 ##
####################################################################################################

# 存储格式： 【数据类型: simple, normal, private】【动作类型: list, new, delete, modify, display, auth 】
ext_data_info = {
    'simple': {
        'list':{
            'title': '明文数据信息列表',
            'desc': '信息内容明文存储',
            'data_type': 'simple',
        },
        'new':{
            'title': '添加明文数据信息',
            'desc': '信息内容明文存储',
            'data_type': 'simple',
        },
        'delete':{
            'title': '删除明文数据信息',
            'desc': '信息内容明文存储',
            'data_type': 'simple',
        },
        'modify':{
            'title': '修改明文数据信息',
            'desc': '信息内容明文存储',
            'data_type': 'simple',
        },
        'display':{
            'title': '查看明文数据信息',
            'desc': '信息内容明文存储',
            'data_type': 'simple',
        },
        'auth':{
            'title': '验证明文密码',
            'desc': '请输入明文密码',
            'data_type': 'simple',
        },
    },

    'normal': {
        'list':{
            'title': '普通数据信息列表',
            'desc': '信息内容用普通密码加密',
            'data_type': 'normal',
        },
        'new':{
            'title': '添加普通数据信息',
            'desc': '信息内容用普通密码加密',
            'data_type': 'normal',
        },
        'delete':{
            'title': '删除普通数据信息',
            'desc': '信息内容用普通密码加密',
            'data_type': 'normal',
        },
        'modify':{
            'title': '修改普通数据信息',
            'desc': '信息内容用普通密码加密',
            'data_type': 'normal',
        },
        'display':{
            'title': '查看普通数据信息',
            'desc': '信息内容用普通密码加密',
            'data_type': 'normal',
        },
        'auth':{
            'title': '验证普通密码',
            'desc': '请输入普通密码',
            'data_type': 'normal',
        },
    },

    'private': {
        'list':{
            'title': '重要数据信息列表',
            'desc': '信息内容用重要密码加密',
            'data_type': 'private',
        },
        'new':{
            'title': '添加重要数据信息',
            'desc': '信息内容用重要密码加密',
            'data_type': 'private',
        },
        'delete':{
            'title': '删除重要数据信息',
            'desc': '信息内容用重要密码加密',
            'data_type': 'private',
        },
        'modify':{
            'title': '修改重要数据信息',
            'desc': '信息内容用重要密码加密',
            'data_type': 'private',
        },
        'display':{
            'title': '查看重要数据信息',
            'desc': '信息内容用重要密码加密',
            'data_type': 'private',
        },
        'auth':{
            'title': '验证重要密码',
            'desc': '请输入重要密码',
            'data_type': 'private',
        },
    },
}


INFO_DATA_TYPE_LIST = ['simple', 'normal', 'private']

# 浏览信息数据
def vf_data(request, data_type):
    if not request.user.is_authenticated:
        return redirect('%s?next=%s' % (settings.LOGIN_URL, request.path))

    if data_type not in INFO_DATA_TYPE_LIST:
        return Http404("数据类型错误：{}".format(data_type))

    if request.method == 'GET':
        info_list = msf_get_data_model_list(data_type, request.user)
        query_text = request.GET.get('query_text', '').strip()
        if query_text:
            info_list = [ x for x in info_list if query_text in x.desc ]

        page_num = request.GET.get('page', '1').strip()
        paginator = Paginator(info_list, 5)
        v_page = paginator.page(page_num)
        v_pindex = page_num
        v_info_list = v_page.object_list

        ext_info = ext_data_info[data_type]['list']
        ext_info['query_text'] = query_text
        context = {"info_list": v_info_list, "ext_info": ext_info, "pindex": v_pindex, "page": v_page}
        return render(request, 'private_info/main-data.html', context=context)
    else:
        return Http404("不支持的方法")


# 新增、修改、删除、显示隐私数据前先验证
def vf_data_auth(request, data_type, data_id, action):
    if not request.user.is_authenticated:
        return redirect('%s?next=%s' % (settings.LOGIN_URL, request.path))

    # 检查数据类型是否正确
    if data_type not in INFO_DATA_TYPE_LIST:
        return Http404("数据类型错误：{}".format(data_type))
    password_type = data_type
    if request.method == 'GET':
        obj_form_password = fsf_get_new_password_form(password_type, 'auth')
        ext_info = ext_data_info[data_type]['auth']
        ext_info['action'] = action
        ext_info['data_id'] = data_id
        context = {"form": obj_form_password, "ext_info": ext_info}
        return render(request, 'private_info/main-data-auth.html', context=context)

    elif request.method == 'POST':
        obj_form_password = fsf_get_post_password_form(password_type, 'auth', request)
        if obj_form_password.is_valid():
            # 读取密码
            password = obj_form_password.cleaned_data['password']
            # 验证密码
            if not msf_password_is_valid(password_type, password, request.user):
                messages.warning(request, "密码错误！")
                ext_info = ext_data_info[data_type]['auth']
                ext_info['action'] = action
                ext_info['data_id'] = data_id
                ext_info['data_type'] = data_type
                context = {"form": obj_form_password, "ext_info": ext_info}
                return render(request, 'private_info/main-data-auth.html', context=context)

            # 密码验证通过，根据 action 准备页面。
            obj_form = fsf_get_data_form(data_type, action)
            if not obj_form:
                return Http404("不支持的操作：{}".format(action))
            if action == 'modify':
                obj_form.fields['password'].initial = password
                obj_model = msf_get_data_model(data_type, data_id, request.user)
                if not obj_model:
                    return Http404("查询数据异常！")
                obj_form.fields['desc'].initial = obj_model.desc
                content = obj_model.content
                if data_type != 'simple':
                    content = uf_decrypt(content, password)
                    if content is None:
                        return Http404("解密数据异常！")
                obj_form.fields['content'].initial = content
            elif action == 'new':
                obj_form.fields['password'].initial = password
            elif action == 'display' or action == 'delete':
                obj_model = msf_get_data_model(data_type, data_id, request.user)
                if not obj_model:
                    return Http404("查询数据异常！")
                obj_form.fields['desc'].initial = obj_model.desc
                content = obj_model.content
                if data_type != 'simple':
                    content = uf_decrypt(content, password)
                    if content is None:
                        return Http404("解密数据异常！")
                obj_form.fields['content'].initial = content
            else:
                return Http404("不支持的操作：{}".format(action))

            ext_info = ext_data_info[data_type][action]
            ext_info['data_id'] = data_id
            context = {"form": obj_form, "ext_info": ext_info}
            if action == 'new':
                return render(request, 'private_info/main-data-new.html', context=context)
            elif action == 'modify':
                return render(request, 'private_info/main-data-modify.html', context=context)
            elif action == 'display':
                return render(request, 'private_info/main-data-display.html', context=context)
            elif action == 'delete':
                return render(request, 'private_info/main-data-delete.html', context=context)
        else:
            messages.warning(request, "输入有误，请检查表单！")
            ext_info = ext_data_info[data_type]['auth']
            ext_info['action'] = action
            context = {"form": obj_form_password, "ext_info": ext_info}
            return render(request, 'private_info/main-data-auth.html', context=context)
    else:
        return Http404("不支持的方法")


# 新增信息数据
def vf_data_new(request, data_type):
    if not request.user.is_authenticated:
        return redirect('%s?next=%s' % (settings.LOGIN_URL, request.path))

    # 检查数据类型是否正确
    if data_type not in INFO_DATA_TYPE_LIST:
        return Http404("数据类型错误：{}".format(data_type))

    # 检查密码是否已设置
    password_type = data_type
    if not msf_password_is_set(password_type, request.user):
        messages.info(request, "请先设置密码！")
        return redirect('private_info:vn-password-new', password_type=password_type)

    # 显示新增页面
    if request.method == 'GET':
        return redirect('private_info:vn-data-auth', data_type=data_type, data_id=0, action='new')

    # 新增数据提交处理
    elif request.method == 'POST':
        obj_form_data = fsf_get_post_data_form(data_type, 'new', request)
        if obj_form_data.is_valid():
            desc = obj_form_data.cleaned_data['desc']
            content = obj_form_data.cleaned_data['content']
            password = obj_form_data.cleaned_data['password']
            if not msf_password_is_valid(password_type, password, request.user):
                return Http404("密码错误！")  # 正常流程不会到这

            # 保存数据
            obj_model_data = msf_get_new_data_model(data_type)
            result = msf_save_data_model(data_type, password, desc, content, request.user, obj_model_data)
            if result:
                messages.success(request, "新增数据成功。")
            else:
                messages.error(request, "保存数据失败！")

            # 重定向到浏览界面
            return redirect('private_info:vn-data', data_type=data_type)

        else:
            messages.warning(request, "输入有误，请检查表单！")
            context = {"form": obj_form_data, "ext_info": ext_data_info[data_type]['new']}
            return render(request, 'private_info/main-data-new.html', context=context)

    else:
        return Http404("不支持的方法")




# 修改数据提交
def vf_data_modify(request, data_type, data_id):
    if not request.user.is_authenticated:
        return redirect('%s?next=%s' % (settings.LOGIN_URL, request.path))
    # 检查数据类型是否正确
    if data_type not in INFO_DATA_TYPE_LIST:
        return Http404("数据类型错误：{}".format(data_type))

    password_type = data_type
    obj_model_data = msf_get_data_model(data_type, data_id, request.user)

    if request.method == 'GET':
        # 重定向到验证步骤
        return redirect('private_info:vn-data-auth', data_type=data_type, data_id=data_id, action='modify')

    elif request.method == 'POST':
        obj_form_data = fsf_get_post_data_form(data_type, 'modify', request)
        if obj_form_data.is_valid():
            # 从表单获取输入
            password = obj_form_data.cleaned_data['password']
            desc = obj_form_data.cleaned_data['desc']
            content = obj_form_data.cleaned_data['content']
            obj_model_data = msf_get_data_model(data_type, data_id, request.user)
            result = msf_save_data_model(data_type, password, desc, content, request.user, obj_model_data)
            if not result:
                messages.error(request, "数据修改失败！")
            else:
                messages.success(request, "数据修改成功！")
            # 返回修改结果
            return redirect('private_info:vn-data', data_type=data_type)

        else:  # 表单验证问题
            messages.warning(request, "输入有误，请检查表单！")
            context = {"form": obj_form_data, "ext_info": ext_data_info[data_type]['modify']}
            return render(request, 'private_info/main-data-modify.html', context=context)
    else:
        return Http404("不支持的方法: {}".format(request.method))


def vf_data_display(request, data_type, data_id):
    if not request.user.is_authenticated:
        return redirect('%s?next=%s' % (settings.LOGIN_URL, request.path))

    if data_type not in INFO_DATA_TYPE_LIST:
        return Http404("数据类型错误：{}".format(data_type))

    if request.method == 'GET':
        return redirect('private_info:vn-data-auth', data_type=data_type, data_id=data_id, action='display')

    elif request.method == 'POST':
        return redirect('private_info:vn-data', data_type=data_type)

    else:
        return Http404("不支持的方法")


def vf_data_delete(request, data_type, data_id):
    if not request.user.is_authenticated:
        return redirect('%s?next=%s' % (settings.LOGIN_URL, request.path))

    if data_type not in INFO_DATA_TYPE_LIST:
        return Http404("数据类型错误：{}".format(data_type))

    if request.method == 'GET':
        return redirect('private_info:vn-data-auth', data_type=data_type, data_id=data_id, action='delete')

    elif request.method == 'POST':
        obj_model_data = msf_get_data_model(data_type, data_id, request.user)
        if obj_model_data:
            obj_model_data.delete()
            messages.success(request, "删除数据成功！")
        else:
            messages.info(request, "数据不存在！")
        return redirect('private_info:vn-data', data_type=data_type)

    else:
        return Http404("不支持的方法")


