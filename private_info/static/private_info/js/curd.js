function checkAll() {
    var all = document.getElementById("checkAll");

    if (all.checked == true) {
        var ones = document.getElementsByName("item");
        for (var i = 0; i <= ones.length; i++) {
            ones[i].checked = true;
        }
    } else {
        var ones = document.getElementsByName("item");
        for (var i = 0; i <= ones.length; i++) {
            ones[i].checked = false;
        }
    }
}

function checkOne() {
    var one=document.getElementsByName("item");
    one.checked=true;
}

function getValues() {
    var valArr=[];
    var ones=document.getElementsByName('item');
    for (var i=0;i<ones.length;i++){
        if (ones[i].checked==true){
            valArr[i]=ones[i].value
        }
    }
    if (valArr.length!=0){
        // var vals = valArr.join(',');
        // alert(valArr);
        $.ajax({　　　　　　　#地址一定要正确
            url:"deleteall/",　　　　　　　#全部大写
            type:'POST',
            contenType:'application/json',　　　　　　　#不加这个，ajax会将结果后边加个[]，例如{'vals[]':[4,6,8]}
            traditional:true,　　　　　　  #不加这个，会报服务器终止了一个在运行的程序
            async: false,
            data:{
                'vals':valArr
            },
            success:function(){
                alert("删除成功");
            },
            error:function(){
                alert("删除失败");
            }
        })
    }
    else {
        var error_m="请选择数据";
        alert(error_m);
    }
}