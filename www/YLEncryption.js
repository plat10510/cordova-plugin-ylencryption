var exec = require('cordova/exec');


exports.encrypt = function (parms, success, error) {
    exec(success, error, 'YLEncryption', 'encrypt', [parms]);
};

exports.decrypt = function (parms, success, error) {
    exec(success, error, 'YLEncryption', 'decrypt', [parms]);
};
