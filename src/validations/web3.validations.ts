import Joi from 'joi';
import { AppRoles } from '@user/user.type';

const ethereumAddressPattern = /^0x[a-fA-F0-9]{40}$/;
const hexSignaturePattern = /^0x[a-fA-F0-9]+$/;


export const requestNonceValidationSchema = Joi.object({
  walletAddress: Joi.string()
    .pattern(ethereumAddressPattern)
    .required()
    .messages({
      'string.pattern.base': 'Invalid Ethereum wallet address',
      'any.required': 'Wallet address is required',
    }),
  appRole: Joi.string()
    .valid(...Object.values(AppRoles))
    .optional()
    .messages({
      'any.only': 'Invalid appRole provided',
    }),
});

export const verifySignatureValidationSchema = Joi.object({
  walletAddress: Joi.string()
    .pattern(ethereumAddressPattern)
    .required()
    .messages({
      'string.pattern.base': 'Invalid Ethereum wallet address',
      'any.required': 'Wallet address is required',
    }),
  signature: Joi.string()
    .pattern(hexSignaturePattern)
    .required()
    .messages({
      'string.pattern.base': 'Invalid signature format',
      'any.required': 'Signature is required',
    }),
  message: Joi.string().required().messages({
    'any.required': 'Message is required',
  }),
});
