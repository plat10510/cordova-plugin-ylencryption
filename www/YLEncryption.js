var exec = require('cordova/exec');

function YLEncryption(){
    
}

YLEncryption.prototype.encrypt = function(options,successCallback,errorCallback){
    exec(successCallback, errorCallback, 'YLEncryption', 'encrypt', [options]);
}

YLEncryption.prototype.decrypt = function(options,successCallback,errorCallback){
    exec(successCallback, errorCallback, 'YLEncryption', 'decrypt', [options]);
}


YLEncryption.install = function(){
    if(!window.plugins){
        window.plugins = {};
    }

    window.plugins.ylencryption = new YLEncryption();

    return window.plugins.ylencryption;
}

cordova.addConstructor(YLEncryption.install);
