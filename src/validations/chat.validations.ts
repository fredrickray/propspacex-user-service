import Joi from 'joi';

const uuidValidation = Joi.string().uuid().required();

export const createConversationValidationSchema = Joi.object({
  buyerId: uuidValidation,
  agentId: uuidValidation,
  propertyId: Joi.string().uuid().optional(),
});

export const sendMessageValidationSchema = Joi.object({
  conversationId: uuidValidation,
  senderId: uuidValidation,
  body: Joi.string().trim().min(1).max(5000).required(),
  messageType: Joi.string().valid('text').optional(),
  metadata: Joi.object().optional().allow(null),
});

export const listConversationsValidationSchema = Joi.object({
  userId: uuidValidation,
  page: Joi.number().integer().min(1).optional(),
  limit: Joi.number().integer().min(1).max(100).optional(),
});

export const listConversationMessagesValidationSchema = Joi.object({
  conversationId: uuidValidation,
  userId: uuidValidation,
  page: Joi.number().integer().min(1).optional(),
  limit: Joi.number().integer().min(1).max(200).optional(),
});

export const markConversationReadValidationSchema = Joi.object({
  conversationId: uuidValidation,
  userId: uuidValidation,
});
