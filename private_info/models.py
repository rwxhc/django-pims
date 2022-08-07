from django.db import models
from django.contrib.auth.models import User

from .utils import uf_hash
from .utils import uf_encrypt
from .utils import uf_decrypt


#######################################################
##  密码数据                                          ##
#######################################################

# 用户超级密码，用于加密其他密码，找回其他密码。
class UserRecoverPassword(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    password = models.CharField(max_length=512)
    prompt = models.CharField(max_length=512)

# 用户简单密码，用于保护明文数据
class UserSimplePassword(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    password = models.CharField(max_length=512)
    encrypt_password = models.CharField(max_length=512)
    prompt = models.CharField(max_length=512)

# 用户普通密码，用于保护普通数据
class UserNormalPassword(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    password = models.CharField(max_length=512)
    encrypt_password = models.CharField(max_length=512)
    prompt = models.CharField(max_length=512)

# 用户重要密码，用保护重要数据
class UserPrivatePassword(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    password = models.CharField(max_length=512)
    encrypt_password = models.CharField(max_length=512)
    prompt = models.CharField(max_length=512)


# 获取密码模型类
def __get_password_model_class(password_type:str):
    """
    password_type: recover, simple, normal, private
    """
    if password_type == 'recover':
        cls_password = UserRecoverPassword
    elif password_type == 'simple':
        cls_password = UserSimplePassword
    elif password_type == 'normal':
        cls_password = UserNormalPassword
    elif password_type == 'private':
        cls_password = UserPrivatePassword
    else:
        return None
    return cls_password


# 查询用户密码数据
def msf_get_password_model(password_type:str, user:User):
    cls_password = __get_password_model_class(password_type)
    if cls_password:
        obj_password_list = cls_password.objects.filter(user=user)
        if obj_password_list:
            return obj_password_list[0]
    return None


# 根据密码类型新建一个模型数据对象
def msf_get_new_password_model(password_type:str):
    cls_password = __get_password_model_class(password_type)
    if not cls_password:
        return None
    return cls_password()


# 检查口令是否设置
def msf_password_is_set(password_type:str, user:User):
    obj_model_password = msf_get_password_model(password_type, user)
    return obj_model_password is not None


# 检查超级密码是否设置
def msf_recover_password_is_set(user:User):
    return msf_password_is_set('recover', user)


# 密码是否匹配
def msf_password_is_valid(password_type: str, password: str, user: User):
    obj_model_password = msf_get_password_model(password_type, user)
    if not obj_model_password:
        return False
    hash_password = uf_hash(password)
    return hash_password == obj_model_password.password


# 保存超级密码数据
def msf_save_recover_password_model(password:str, prompt:str, user:User, obj_model):
    if not obj_model:
        return False
    obj_model.password = uf_hash(password)
    obj_model.prompt = prompt
    obj_model.user = user
    obj_model.save()
    return True


# 保存其他密码数据
def msf_save_password_model(recover_password:str, password:str, prompt:str, user:User, obj_model):
    if not obj_model:
        return False
    obj_model.password = uf_hash(password)
    obj_model.encrypt_password = uf_encrypt(password, recover_password)
    obj_model.prompt = prompt
    obj_model.user = user
    obj_model.save()
    return True


# 修改超级密码附加业务逻辑处理
def msf_change_recover_password(old_password:str, new_password:str, new_prompt:str, obj_model):
    if not obj_model:
        return False, "参数错误：超级密码数据为空！"

    if not msf_password_is_valid('recover', old_password, obj_model.user):
        return False, "旧超级密码验证失败！"

    # 解密其他密码，用新超级密码重新加密。
    obj_model_simple = msf_get_password_model('simple', obj_model.user)
    obj_model_normal = msf_get_password_model('normal', obj_model.user)
    obj_model_private = msf_get_password_model('private', obj_model.user)
    for obj_model_other in [obj_model_simple, obj_model_normal, obj_model_private]:
        if obj_model_other:
            clear_other_password = uf_decrypt(obj_model_other.encrypt_password, old_password)
            if not clear_other_password:
                return False, "解密其他密码失败！"
            obj_model_other.encrypt_password = uf_encrypt(clear_other_password, new_password)
            obj_model_other.save()

    # 保存新超级口令
    obj_model.password = uf_hash(new_password)
    obj_model.prompt = new_prompt
    obj_model.save()
    return True, "超级密码修改成功！"


# 修改其他密码附加业务逻辑处理
def msf_change_password(password_type:str, recover_password:str, new_password:str, new_prompt:str, obj_model):
    if not obj_model:
        return False, "参数错误：密码数据为空！"

    if not msf_password_is_valid('recover', recover_password, obj_model.user):
        return False, "超级密码验证失败！"

    # 读取加密数据并重新加密
    data_type = password_type
    if data_type != 'simple':
        # 计算明文密码
        clear_other_password = uf_decrypt(obj_model.encrypt_password, recover_password)
        if not clear_other_password:
            return False, "密码解密失败！"
        obj_model_data_list = msf_get_data_model_list(data_type, obj_model.user)
        if obj_model_data_list:
            for obj_model_data in obj_model_data_list:
                clear_content = uf_decrypt(obj_model_data.content,  clear_other_password)
                if not clear_content:
                    return False, "解密数据失败！"
                obj_model_data.content = uf_encrypt(clear_content, new_password)
                obj_model_data.save()

    # 保存新密码
    obj_model.password = uf_hash(new_password)
    obj_model.encrypt_password = uf_encrypt(new_password, recover_password)
    obj_model.prompt = new_prompt
    obj_model.save()
    return True, "密码修改成功！"


#######################################################
##  信息数据                                          ##
#######################################################


# 明文数据，仅用简单密码保护数据，不加密
class UserSimpleData(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    content = models.CharField(max_length=8192)
    desc = models.CharField(max_length=512)

# 普通数据，用普通密码加密
class UserNormalData(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    content = models.CharField(max_length=8192)
    desc = models.CharField(max_length=512)

# 重要数据，用重要密码加密
class UserPrivateData(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    content = models.CharField(max_length=8192)
    desc = models.CharField(max_length=512)


# 获取模型类
def __get_data_model_class(data_type:str):
    if data_type == 'simple':
        cls_info = UserSimpleData
    elif data_type == 'normal':
        cls_info = UserNormalData
    elif data_type == 'private':
        cls_info = UserPrivateData
    else:
        return None
    return cls_info


# 获取信息数据列表
def msf_get_data_model_list(data_type:str, user:User):
    cls_info = __get_data_model_class(data_type)
    if not cls_info:
        return None
    return cls_info.objects.filter(user=user)


# 获取信息数据
def msf_get_data_model(data_type:str, data_id:int, user:User):
    cls_info = __get_data_model_class(data_type)
    if not cls_info:
        return None
    return cls_info.objects.get(pk=data_id)



# 获取新模型对象
def msf_get_new_data_model(data_type:str):
    cls_info = __get_data_model_class(data_type)
    if not cls_info:
        return None
    return cls_info()


# 保存信息数据
def msf_save_data_model(data_type:str, password:str, desc:str, content:str, user:User, obj_model):
    if not obj_model:
        return False
    obj_model.desc = desc
    obj_model.content = content
    obj_model.user = user

    if data_type != 'simple':
        obj_model.content = uf_encrypt(content, password)

    obj_model.save()
    return True
