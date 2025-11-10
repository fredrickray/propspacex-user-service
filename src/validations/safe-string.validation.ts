import Joi from 'joi';

const safeString = Joi.string()
  .pattern(/^[^<>`"'\\;%]*$/)
  .messages({
    'string.pattern.base': '{{#label}} contains unsafe characters',
  });

export default safeString;
