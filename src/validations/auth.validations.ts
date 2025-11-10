import Joi from 'joi';
import safeString from './safe-string.validation.js';
export const userPasswordSchema = Joi.string()
  .min(8)
  .pattern(/[a-z]/, 'lowercase letter')
  .pattern(/[A-Z]/, 'uppercase letter')
  .pattern(/[0-9]/, 'number')
  // .pattern(/[!@#$%^&*(),.?":{}|<>]/, 'special character')
  .required()
  .error((errors) => {
    errors.forEach((err) => {
      switch (err.code) {
        case 'string.empty':
          err.message = 'Password is required';
          break;
        case 'string.min':
          err.message = 'Password must be at least 8 characters long';
          break;
        case 'string.pattern.name':
          if (err.local?.name === 'lowercase letter') {
            err.message = 'Password must contain at least 1 lowercase letter';
          } else if (err.local?.name === 'uppercase letter') {
            err.message = 'Password must contain at least 1 uppercase letter';
          } else if (err.local?.name === 'number') {
            err.message = 'Password must contain at least 1 number';
          }
          break;
        default:
          err.message = 'Invalid password format';
          break;
      }
    });
    return errors;
  });

export const signupValidationSchema = Joi.object({
  email: safeString.label('Email').email().required().lowercase(),
});

export const verifyOTPValidationSchema = Joi.object({
  email: safeString.label('Email').email().required(),
  otp: safeString.label('OTP').required().length(6),
});

export const resendOTPValidationSchema = Joi.object({
  email: safeString.label('Email').email().lowercase().required(),
});

export const signinValidationSchema = Joi.object({
  email: safeString.label('Email').email().required(),
  password: safeString.label('Password').min(8).required(),
  deviceToken: safeString.label('Device Token').allow(null, ''),
  deviceType: Joi.string().allow(null, ''),
  rememberMe: Joi.boolean().required(),
});

export const forgotPasswordValidationSchema = Joi.object({
  email: safeString
    .label('Email')
    .email({ tlds: { allow: false } }) // avoid false positives from bad TLDs
    .required()
    .messages({
      'string.base': 'Email must be a string',
      'string.email': 'Email must be a valid email address',
      'any.required': 'Email is required',
    }),
});
