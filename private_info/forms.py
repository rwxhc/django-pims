
from django import forms
from django.core.exceptions import ValidationError
from django.core.handlers.wsgi import WSGIRequest

# 设置超级密码表单
class NewRecoverPasswordForm(forms.Form):
    password = forms.CharField(label='输入密码', min_length=6, max_length=512, widget=forms.PasswordInput)
    password.widget.attrs.update(size='50')
    confirm_password = forms.CharField(label='确认密码', min_length=6, max_length=512, widget=forms.PasswordInput)
    confirm_password.widget.attrs.update(size='50')
    prompt = forms.CharField(widget=forms.Textarea(attrs={'cols': '50', 'rows': '10'}),
                             label='密码提示', max_length=512, help_text='提示信息仅用于辅助回忆密码。')

    # 校验函数
    def clean(self):
        if self.cleaned_data.get('password') != self.cleaned_data.get('confirm_password'):
            raise ValidationError('两次密码输入不一致！')
        return self.cleaned_data

# 修改超级密码表单
class ModifyRecoverPasswordForm(forms.Form):
    old_password = forms.CharField(label='旧的密码', min_length=6, max_length=512, widget=forms.PasswordInput)
    old_password.widget.attrs.update(size='50')
    password = forms.CharField(label='新的密码', min_length=6, max_length=512, widget=forms.PasswordInput)
    password.widget.attrs.update(size='50')
    confirm_password = forms.CharField(label='确认密码', min_length=6, max_length=512, widget=forms.PasswordInput)
    confirm_password.widget.attrs.update(size='50')
    prompt = forms.CharField(widget=forms.Textarea(attrs={'cols': '50', 'rows': '10'}),
                             label='密码提示', max_length=512, help_text='提示信息仅用于辅助回忆密码。')

    # 校验函数
    def clean(self):
        if self.cleaned_data.get('old_password') == self.cleaned_data.get('password'):
            raise ValidationError('新密码不能和旧密码一样！')
        if self.cleaned_data.get('password') != self.cleaned_data.get('confirm_password'):
            raise ValidationError('两次密码输入不一致！')
        return self.cleaned_data

# 设置其他密码表单
class NewPasswordForm(forms.Form):
    recover_password = forms.CharField(widget=forms.HiddenInput)
    password = forms.CharField(label='输入密码', min_length=6, max_length=512, widget=forms.PasswordInput)
    password.widget.attrs.update(size='50')
    confirm_password = forms.CharField(label='确认密码', min_length=6, max_length=512, widget=forms.PasswordInput)
    confirm_password.widget.attrs.update(size='50')
    prompt = forms.CharField(widget=forms.Textarea(attrs={'cols': '50', 'rows': '10'}),
                             label='密码提示', max_length=512, help_text='提示信息仅用于辅助回忆密码。')

    # 校验函数
    def clean(self):
        if self.cleaned_data.get('password') != self.cleaned_data.get('confirm_password'):
            raise ValidationError('两次密码输入不一致！')
        return self.cleaned_data


# 密码已设置界面，仅显示提示信息
class PasswordForm(forms.Form):
    prompt = forms.CharField(widget=forms.Textarea(attrs={'cols': '50', 'rows': '10'}),
                             label='密码提示', max_length=512, disabled=True, help_text='提示信息仅用于辅助回忆密码。')

# 找回密码，输入超级密码
class AuthPasswordForm(forms.Form):
    option_1 = forms.CharField(widget=forms.HiddenInput, required=False)
    option_2 = forms.CharField(widget=forms.HiddenInput, required=False)
    option_3 = forms.CharField(widget=forms.HiddenInput, required=False)
    password = forms.CharField(label='输入密码', min_length=6, max_length=512, widget=forms.PasswordInput)
    password.widget.attrs.update(size='50')

# 查看密码表单
class DisplayPasswordForm(forms.Form):
    password = forms.CharField(label='当前密码', min_length=6, max_length=512, disabled=True)
    password.widget.attrs.update(size='50')
    prompt = forms.CharField(widget=forms.Textarea(attrs={'cols': '50', 'rows': '10'}),
                             label='密码提示', max_length=512, disabled=True)

# 获取密码表单类
def __get_password_form_class(password_type:str, action:str):
    """
    password_type: recover, simple, normal, private
    action: new, get, modify, auth, display
    """
    if password_type == 'recover':
        if action == 'new':
            cls_form = NewRecoverPasswordForm
        elif action == 'get':
            cls_form = PasswordForm
        elif action == 'modify':
            cls_form = ModifyRecoverPasswordForm
        else:
            return None
    elif password_type == 'simple' or password_type == 'private' or password_type == 'normal':
        if action == 'new':
            cls_form = NewPasswordForm
        elif action == 'get':
            cls_form = PasswordForm
        elif action == 'modify':
            cls_form = NewPasswordForm
        elif action == 'auth':
            cls_form = AuthPasswordForm
        elif action == 'display':
            cls_form = DisplayPasswordForm
        else:
            return None
    else:
        return None
    return cls_form


# 获取密码表单对象
def fsf_get_new_password_form(password_type:str, action:str):
    cls_form = __get_password_form_class(password_type, action)
    if cls_form:
        return cls_form()
    return None


# 从POST请求中获取表单对象
def fsf_get_post_password_form(password_type:str, action:str, request:WSGIRequest):
    cls_form = __get_password_form_class(password_type, action)
    if cls_form:
        return cls_form(request.POST)
    return None


################################################################################################
#  数据相关表单
################################################################################################

# 设置或修改明文表单
class ClearDataForm(forms.Form):
    desc = forms.CharField(label='信息描述', min_length=1, max_length=512)
    desc.widget.attrs.update(size='50')
    content = forms.CharField(widget=forms.Textarea(attrs={'cols': '50', 'rows': '20'}),
                             label='信息内容', max_length=1024*1024)


# 设置或修改需要加密信息表单
class EncryptDataForm(forms.Form):
    password = forms.CharField(widget=forms.HiddenInput, required=False)
    password.widget.attrs.update(size='50')
    desc = forms.CharField(label='信息描述', min_length=1, max_length=512)
    desc.widget.attrs.update(size='50')
    content = forms.CharField(widget=forms.Textarea(attrs={'cols': '50', 'rows': '20'}),
                             label='信息内容', max_length=1024*1024)


# 获取密码表单类
def __get_info_form_class(data_type:str, action:str):
    """
    data_type: simple, normal, private
    action: new, modify, auth, display, delete
    """
    if data_type == 'simple' or data_type == 'normal' or data_type == 'private':
        if action == 'new' or action == 'modify':
            return EncryptDataForm
        elif action == 'auth':
            return AuthPasswordForm
        elif action == 'display' or action == 'delete':
            return ClearDataForm
    return None


# 获取信息表单
def fsf_get_data_form(data_type:str, action:str):
    cls_form = __get_info_form_class(data_type, action)
    if not cls_form:
        return None
    return cls_form()

# 从POST请求中获取表单
def fsf_get_post_data_form(data_type:str, action:str, request:WSGIRequest):
    cls_form = __get_info_form_class(data_type, action)
    if not cls_form:
        return None
    return cls_form(request.POST)

################################################################################################
#  用户注册表单
################################################################################################

class UserRegistryForm(forms.Form):
    username = forms.CharField(label='用户名', min_length=1, max_length=512, help_text="用户名可以是中文或英文或数字")
    username.widget.attrs.update(size='50')
    password = forms.CharField(label='登录密码', min_length=6, max_length=512, widget=forms.PasswordInput, help_text="密码至少6位字符")
    password.widget.attrs.update(size='50')
    confirm_password = forms.CharField(label='确认密码', min_length=6, max_length=512, widget=forms.PasswordInput)
    confirm_password.widget.attrs.update(size='50')

    # 校验函数
    def clean(self):
        if self.cleaned_data.get('password') != self.cleaned_data.get('confirm_password'):
            raise ValidationError('两次密码输入不一致！')
        return self.cleaned_data


################################################################################################
#  用户修改登录密码
################################################################################################

# 修改login密码表单
class ModifyLoginPasswordForm(forms.Form):
    old_password = forms.CharField(label='旧的密码', min_length=6, max_length=512, widget=forms.PasswordInput)
    old_password.widget.attrs.update(size='50')
    password = forms.CharField(label='新的密码', min_length=6, max_length=512, widget=forms.PasswordInput)
    password.widget.attrs.update(size='50')
    confirm_password = forms.CharField(label='确认密码', min_length=6, max_length=512, widget=forms.PasswordInput)
    confirm_password.widget.attrs.update(size='50')

    # 校验函数
    def clean(self):
        if self.cleaned_data.get('password') != self.cleaned_data.get('confirm_password'):
            raise ValidationError('两次密码输入不一致！')
        return self.cleaned_data

