"use strict";

var passport = module.parent.require('passport');
var PassportLocal = module.parent.require('passport-local').Strategy;
var request = module.parent.require('request');
var async = module.parent.require('async');
var db = module.parent.require('./database');
var user = module.parent.require('./user');

module.exports = {
    auth: function() {
        passport.use(new PassportLocal({passReqToCallback: true}, function(req, username, password, next) {
            request({
                method: 'POST',
                url: '/login',
                baseUrl: process.env.RG_AUTH_HOST || 'docker:4000',
                json: true,
                body: {
                    username: username,
                    password: password
                }
            }, function(err, res) {
                if (err || res.statusCode !== 200) {
                    next(err || new Error());
                    return;
                }
                var uid, userData = {};
                async.waterfall([
                    function (next) {
                        user.getUidByUserslug(res.body.data.username, next);
                    },
                    function (_uid, next) {
                        if (!_uid) {
                            return next(new Error('[[error:no-user]]'));
                        }
                        uid = _uid;
                        user.auth.logAttempt(uid, req.ip, next);
                    },
                    function (next) {
                        async.parallel({
                            userData: function(next) {
                                db.getObjectFields('user:' + uid, ['banned'], next);
                            },
                            isAdmin: function(next) {
                                user.isAdministrator(uid, next);
                            }
                        }, next);
                    },
                    function (result, next) {
                        userData = result.userData;
                        userData.uid = uid;
                        userData.isAdmin = result.isAdmin;

                        if (!result.isAdmin && parseInt(meta.config.allowLocalLogin, 10) === 0) {
                            return next(new Error('[[error:local-login-disabled]]'));
                        }
                        if (userData.banned && parseInt(userData.banned, 10) === 1) {
                            return next(new Error('[[error:user-banned]]'));
                        }
                        user.auth.clearLoginAttempts(uid);
                        next(null, userData, '[[success:authentication-successful]]');
                    }
                ], next);
            });
        }));
    }
};