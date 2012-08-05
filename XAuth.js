/*
 * Xauth.js. A simple XAuth access lib for 500px.com
 * Copyright (c)  2012 Krish Verma
 * Released under the Apache License 
 *
 * NOTICE!
 * Xauth.js requires oauth.js and sha1.js
 *
 * <script src="sha1.js">
 * <script src="oauth.js">
 * <script src="Xauth.js">
 */

/**
 * @class XAuth class
 * @constructor
 * @requires sha1.js <a href="http://code.google.com/p/oauth/source/browse/#svn%2Fcode%2Fjavascript">see</a>
 * @requires oauth.js <a href="http://code.google.com/p/oauth/source/browse/#svn%2Fcode%2Fjavascript">see</a>
 * @param {Object} params
 * @param {String} params.consumerKey
 * @param {String} params.consumerSecret
 * @param {String} params.accessToken
 * @param {String} params.accessTokenSecret
 */

function XAuth(params) {
    this._init(params);
};

/**
 * error code and messages
 * @static
 * @constant
 */
XAuth.errors = {
    invalidConsumerInfo : {code : 401, message : 'Consumer key missing'}, 
    invalidAuthError    : {code : 401, message : 'Invalid OAuth Request'}, 
    authorizeError      : {code : 403, message : 'Invalid Username or Password'}, 
    unknown             : {code : 900, message : 'Unknown error'} 
};



/**
 * using default headers for XmlHttpRequest
 * @static
 * @constant
 */
XAuth.defaultHeaders = {
    "Accept-Encoding": "none",
    "Accept-Language": "en",
    "Accept-Charset": "UTF-8",
    "Cookie": ""
};

/**
 * constant oauth version
 * @inner
 * @static
 * @constant
 */
XAuth.OAUTH_VERSION = "1.0";
/**
 * constant oauth signature method
 * @inner
 * @static
 * @constant
 */
XAuth.OAUTH_SIGNATURE_METHOD = "HMAC-SHA1";
/**
 * constant xauth mode
 * @inner
 * @static
 * @constant
 */
XAuth.XAUTH_MODE = "client_auth";

/**
 * fetch_request_token from provider<br>
 *
 * access token is passed as arguments of callback method
 *
 * @param {Object}   params required these parameter
 * @param {String}   params.consumerKey API consumer key
 * @param {String}   params.xauthRequestTokenUrl
 * @param {String}   params.consumerSecret
 * @param {String}   params.userName
 * @param {String}   params.password
 * @param {function} params.success callback on succeeded. This callback method has two arguments, accessToken and accessTokenSecret. 
 * @param {function} [params.error] callback on error. This callback method has two arguments, errorCode and errorMessage.
 */
XAuth.fetch_request_token = function(params) {
    var accessor = {
        consumerSecret: params.consumerSecret,
        tokenSecret: ""
    };

    var message = {
        method: "POST",
        action: params.xauthRequestTokenUrl,
        parameters: {
            oauth_consumer_key: params.consumerKey,
            oauth_signature_method: XAuth.OAUTH_SIGNATURE_METHOD,
            oauth_version: XAuth.OAUTH_VERSION,
            x_auth_username: params.userName,
            x_auth_password: params.password,
            x_auth_mode: XAuth.XAUTH_MODE
        }
    };

    OAuth.setTimestampAndNonce(message);
    OAuth.SignatureMethod.sign(message, accessor);


    var additionalHeaders = {
        "Authorization": 'OAuth oauth_nonce="' + message.parameters.oauth_nonce + '"' 
	    + ', oauth_signature_method="' + message.parameters.oauth_signature_method + '"' 
	    + ', oauth_timestamp="' + message.parameters.oauth_timestamp + '"' 
	    + ', oauth_consumer_key="' + message.parameters.oauth_consumer_key + '"' 
	    + ', oauth_signature="' + encodeURIComponent(message.parameters.oauth_signature) + '"' 
	    + ', oauth_version="' + message.parameters.oauth_version + '"'
    };

    var request = {
        method: message.method,
        action: message.action,
	checkTokenInResponse: true,
        consumerKey: params.consumerKey,
        consumerSecret: params.consumerSecret,
        additionalHeaders: additionalHeaders,
        postData: 'x_auth_username=' + params.userName + '&x_auth_password=' + params.password + '&x_auth_mode=' + message.parameters.x_auth_mode,
        success: XAuth._hasFunction(params, "success") ? params.success : function(token, secret, xauth) {},
        error: XAuth._hasFunction(params, "error") ? params.error : function(err, message) {}
    };

    XAuth._send(request);
}

/**
 * fetch_access_token from provider 500px.com<br>
 *
 * access token is passed as arguments of callback method
 * @param {String}   params.xauthRequestTokenUrl
 * @param {Object}   params required these parameter
 * @param {String}   params.consumerKey API consumer key
 * @param {String}   params.consumerSecret
 * @param {String}   params.userName
 * @param {String}   params.password
 * @param {function} params.success callback on succeeded. This callback method has two arguments, accessToken and accessTokenSecret. 
 * @param {function} [params.error] callback on error. This callback method has two arguments, errorCode and errorMessage.
 */
XAuth.fetch_access_token = function(params) {
    var accessor = {
        consumerKey: params.consumerKey,
        consumerSecret: params.consumerSecret,
        token: params.requestToken,
        tokenSecret: params.requestSecret
    };

    var message = {
        method: "POST",
        action: params.xauthAccessTokenUrl,
        parameters: {
            oauth_consumer_key: params.consumerKey,
            oauth_signature_method: XAuth.OAUTH_SIGNATURE_METHOD,
            oauth_version: XAuth.OAUTH_VERSION,
            oauth_token: params.requestToken,
            x_auth_username: params.userName,
            x_auth_password: params.password,
            x_auth_mode: XAuth.XAUTH_MODE
        }
    };

    OAuth.completeRequest(message, accessor);


    var additionalHeaders = {
        "Authorization": 'OAuth oauth_nonce="' + message.parameters.oauth_nonce + '"' 
	    + ', oauth_signature_method="' + message.parameters.oauth_signature_method + '"' 
	    + ', oauth_timestamp="' + message.parameters.oauth_timestamp + '"' 
	    + ', oauth_consumer_key="' + message.parameters.oauth_consumer_key + '"' 
	    + ', oauth_signature="' + encodeURIComponent(message.parameters.oauth_signature) + '"' 
	    + ', oauth_token="' + encodeURIComponent(message.parameters.oauth_token) + '"' 
	    + ', oauth_version="' + message.parameters.oauth_version + '"'
    };

    var request = {
        method: message.method,
        action: message.action,
	checkTokenInResponse: true,
        consumerKey: params.consumerKey,
        consumerSecret: params.consumerSecret,
        additionalHeaders: additionalHeaders,
        postData: OAuth.SignatureMethod.normalizeParameters('x_auth_username=' + params.userName 
							    + '&x_auth_password=' + params.password 
							    + '&x_auth_mode=' + message.parameters.x_auth_mode),


        success: XAuth._hasFunction(params, "success") ? params.success : function(token, secret, xauth) {},
        error: XAuth._hasFunction(params, "error") ? params.error : function(err, message) {}
    };

    XAuth._send(request);
}

/**
 * XmlHttpRequest wrapper method
 *
 * @private
 * @param {Object} request
 * @param {Object} request.method
 * @param {Object} request.action
 * @param {Object} request.success
 * @param {Object} request.error
 * @param {Object} request.errorMessages
 * @param {Object} [request.additionalHeaders]
 * @param {Object} [request.postData]
 * @param {Object} [request.consumerKey]
 * @param {Object} [request.consumerSecret]
 */
XAuth._send = function(request) {
    var headers = {};
    for (var key in XAuth.defaultHeaders) {
        headers[key] = XAuth.defaultHeaders[key];
    }
    // merge and override headers by additionalHeaders
    for (var key in request.additionalHeaders) {
        headers[key] = request.additionalHeaders[key];
    }
    if (request.method == "POST") {
        headers["Content-Type"] = "application/x-www-form-urlencoded";
    }

    var xhr = new XMLHttpRequest();

    xhr.open(request.method, request.action, true);

    for (var i in headers) {
        xhr.setRequestHeader(i, headers[i]);
    }

    xhr.onreadystatechange = function() {
        if (xhr.readyState == 4) {
            if (xhr.status == 200) {
                // success has been validated already.
                if (true == request.checkTokenInResponse) {
                    // token get
                    var responseParams = OAuth.getParameterMap(xhr.responseText);
                    if (responseParams['oauth_token'] == null || responseParams['oauth_token_secret'] == null) {
                        // response error
                        var message = (request.errorMessages.hasOwnProperty('authError')) ? request.errorMessages.authError : XAuth.errors.invalidAuthError.message;
                        request.error(XAuth.errors.invalidAuthError.code, XAuth.errors.invalidAuthError.message);
                        return;
                    }
                    request.success(responseParams['oauth_token'], responseParams['oauth_token_secret']);
                }
                else {
                    request.success();
                }
            }
            else {
                var code = xhr.status;
                var message = xhr.responseText;
                // error has been validated already.
                if (code == 403) {
                    code = XAuth.errors.authorizeError.code;
                    message = XAuth.errors.authorizeError.message;
                } else if (code == 401 && (message.indexOf(XAuth.errors.invalidConsumerInfo.message) != -1)) {
                    code = XAuth.errors.invalidConsumerInfo.code;
                    message = XAuth.errors.invalidConsumerInfo.message;
                }
                request.error(code, message);
            }
        }
    };

    xhr.send(request.hasOwnProperty("postData") ? request.postData : null);
}

/**
 * execute error callback method
 *
 * @private
 * @param {Object} String
 * @param {function} fn
 * @param {Object} messages
 */
XAuth._executeErrorCallback = function(error, callback, messages) {
    if (!XAuth.errors.hasOwnProperty(error)) {
        // unDefined error
        callback(XAuth.errors.unknown.code, XAuth.errors.unknown.message);
        return;
    }

    var message = (messages != null && messages.hasOwnProperty(error)) ? messages[error] : XAuth.errors[error].message;
    callback(XAuth.errors[error].code, message);
}

/**
 * This returns object has function propety  
 *
 * @private
 * @param {Object} params object
 * @param {String} name   property name
 * @returns {boolean}
 */
XAuth._hasFunction = function(params, name) {
    if (params.hasOwnProperty(name) && typeof params[name] == "function") {
        return true;
    }
    return false;
}

XAuth.prototype = {
    /**
     * initialize
     *
     * @private
     * @param {Object} params
     * @param {Object} params.xauthRequestTokenUrl
     * @param {Object} params.xauthAccessTokenUrl
     * @param {Object} params.consumerKey
     * @param {Object} params.consumerSecret
     * @param {Object} params.accessToken
     * @param {Object} params.accessTokenSecret
     * @param {Object} params.errorMessages
     */
    _init: function(params) {
	this.xauthRequestTokenUrl = params.xauthRequestTokenUrl;
	this.xauthAccessTokenUrl = params.xauthAccessTokenUrl;
        this.consumerKey = params.consumerKey;
        this.consumerSecret = params.consumerSecret;
        this.accessToken = params.accessToken;
        this.accessTokenSecret = params.accessTokenSecret;
        this.errorMessages = params.hasOwnProperty("errorMessages") ? params.errorMessages : {};
    },

    /**
     * to check this object has been Authorized already
     *
     * @return {boolean} true:valid token and secret/false:invalid token and secret
     */
    isAuthorized: function() {
        if (this.accessToken == null || this.accessToken.length == 0 || this.accessTokenSecret == null || this.accessTokenSecret.length == 0) {
            return false;
        }
        return true;
    },

    /**
     * signedcall method
     *
     * @param {Object|String}   params
     * @param {String} params.payload {key value pairs} map obj which is the payload.
     * @param {String} params.method - GET/POST/DELETE/PUT
     * @param {String} params.action URL to interact with.
     * @param {function} [params.success] callback on succeeded.
     * @param {function} [params.error] callback on error. This callback method has two arguments, errorCode and errorMessage.
     * @param {Object} [params.errorMessages] override errorMessage. example params.errorMessages.unknownError = "Duh Wtf!!"
     */
    signedcall: function(params) {
        if (params == null || (typeof params != "object" && typeof params != "String")) {
            return;
        }
        else if (typeof params == "String") {
            params = {
                payload: params
            };
        }
        var errorCallback = XAuth._hasFunction(params, "error") ? params.error : function(code, message) {};

        if (this.consumerKey == null || this.consumerSecret == null) {
            // error : not exist consumer key/secret
            XAuth._executeErrorCallback("invalidConsumerInfo", errorCallback, this.errorMessages);
            return;
        }
        if (!this.isAuthorized()) {
            // error : not exist access token/secret
            XAuth._executeErrorCallback("notAuthorized", errorCallback, this.errorMessages);
            return;
        }
      
        var accessor = {
            consumerSecret: this.consumerSecret,
            tokenSecret: this.accessTokenSecret
        };

        var message = {
            method: params.method,
            action: params.action,
            parameters: {
                oauth_consumer_key: this.consumerKey,
                oauth_signature_method: XAuth.OAUTH_SIGNATURE_METHOD,
                oauth_version: XAuth.OAUTH_VERSION,
                oauth_token: this.accessToken
            }
        };

	if(params.hasOwnProperty("payload")) {
	    OAuth.setParameters(message, params.payload);
	}

	OAuth.completeRequest(message, accessor);
	
	var actionUrl = message.action;
	var postDataPayload = null;

	if(message.method == 'GET')
	    actionUrl = OAuth.addToURL(actionUrl, message.parameters);
	if(message.method == 'POST')
	    postDataPayload  = OAuth.SignatureMethod.normalizeParameters(message.parameters);
	    

        var request = {
            method: message.method,
            action: actionUrl,
            success: XAuth._hasFunction(params, "success") ? params.success : function() {},
            error: errorCallback,
	    postData: postDataPayload,
            additionalHeaders: (params.hasOwnProperty("additionalHeaders")) ? params.additionalHeaders : {},
            errorMessages: this.errorMessages
        };

        XAuth._send(request);
    }
}