import { Router } from "express";
import {
  createNote,
  deleteNoteById,
  getNoteById,
  getNotes,
  updateNoteById,
} from "../controllers/note.controller.js";
import {
  checkToken,
  validateProjectPermission,
} from "../middlewares/auth.middleware.js";
import { UserRolesEnum } from "../utils/constants.js";
import {
  createNoteValidator,
} from "../validators/index.js";
const router = Router();
router.use(checkToken);

router
  .route("/:projectId")
  .get(validateProjectPermission([]), getNotes)
  .post(
    validateProjectPermission([UserRolesEnum.ADMIN]),
    createNoteValidator,
    createNote,
  );

router
  .route("/:projectId/n/:noteId")
  .get(validateProjectPermission([]), getNoteById)
  .put(
    validateProjectPermission([UserRolesEnum.ADMIN]),
    createNoteValidator,
    updateNoteById,
  )
  .get(validateProjectPermission([UserRolesEnum.ADMIN]), deleteNoteById);

export default router;
