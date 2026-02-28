import { Router } from "express";
import {
  createSubtask,
  createTask,
  deleteSubtask,
  deleteTaskById,
  getTaskById,
  getTasks,
  updateSubtask,
  updateTaskById,
} from "../controllers/task.controller.js";
import {
  checkToken,
  validateProjectPermission,
} from "../middlewares/auth.middleware.js";
import { UserRolesEnum } from "../utils/constants.js";
import {
  createSubTaskValidator,
  createTaskValidator,
} from "../validators/index.js";
const router = Router();
router.use(checkToken);

router
  .route("/:projectId")
  .get(validateProjectPermission([]), getTasks)
  .post(
    validateProjectPermission([
      UserRolesEnum.ADMIN,
      UserRolesEnum.PROJECT_ADMIN,
    ]),
    createTaskValidator,
    createTask,
  );

router
  .route("/:projectId/t/:taskId")
  .get(validateProjectPermission([]), getTaskById)
  .put(
    validateProjectPermission([
      UserRolesEnum.ADMIN,
      UserRolesEnum.PROJECT_ADMIN,
    ]),
    createTaskValidator,
    updateTaskById,
  )
  .delete(
    validateProjectPermission([
      UserRolesEnum.ADMIN,
      UserRolesEnum.PROJECT_ADMIN,
    ]),
    deleteTaskById,
  );

router
  .route("/:projectId/t/:taskId/subtasks")
  .post(
    validateProjectPermission([
      UserRolesEnum.ADMIN,
      UserRolesEnum.PROJECT_ADMIN,
    ]),
    createSubTaskValidator,
    createSubtask,
  )
  .put(validateProjectPermission([]), createSubTaskValidator, updateSubtask)
  .delete(
    validateProjectPermission([
      UserRolesEnum.ADMIN,
      UserRolesEnum.PROJECT_ADMIN,
    ]),
    deleteSubtask,
  );

export default router;
