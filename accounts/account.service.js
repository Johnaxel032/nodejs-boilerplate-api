const config = require('config.json');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs')
const crypto = require("crypto");
const { Op } = require('sequelize');
const sendEmail = require('_helpers/send-email');
const db = require('_helpers/db');
const Role = require('_helpers/role');

module.exports = { 
    authenticate, 
    refreshToken, 
    revokeToken,
    register,
    verifyEmail,
    forgotPassword,
    validateResetToken,
    resetPassword, 
    getAll,
    getById,
    create,
    update,
    delete: _delete
};

async function authenticate({isEmail, password, ipAddress}) {
    const account = await db.Account.scope('withHash').findOne({where: { email }});

    if(!account || !account.isVerified || !(await bcrypt.compare(password, account.passwordHash))) {
        throw 'Email or password is incorrect';
    }

    //authentication successful so generate jwt and refresh tokens 
    const jwtToken = generateJwtToke(account);
    const refreshToken = generateRefreshToken(account, ipAddress);

    //save refresh token await refresh token
}