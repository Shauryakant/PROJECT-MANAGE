import { validationResult } from "express-validator";
import { ApiError } from "../utils/api-error.js";
export const validate = (req, res, next) => {
  const errors = validationResult(req);
  if (errors.isEmpty()) {
    return next();
  }
  const extractedErrors = [];
  errors.array().map((err) => {
    extractedErrors.push({ [err.path]: err.message });
  });
  throw new ApiError(500, "There are errors in credentials", extractedErrors);
};
