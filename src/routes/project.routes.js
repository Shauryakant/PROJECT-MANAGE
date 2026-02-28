import { Router } from "express";
import {
  addProjectMemberByProjectId,
  createProject,
  deleteProjectById,
  deleteProjectMemberByProjectId,
  getProjectById,
  getProjectMemberByProjectId,
  getProjects,
  updateProjectById,
  updateProjectMemberRoleInfoByProjectId,
} from "../controllers/project.controller.js";
import {
  checkToken,
  validateProjectPermission,
} from "../middlewares/auth.middleware.js";
import { UserRolesEnum } from "../utils/constants.js";
import {
  addMemberToProjectValidator,
  createProjectValidator,
} from "../validators/index.js";
const router = Router();
router.use(checkToken);
router.route("/").get(getProjects).post(createProjectValidator, createProject);

router
  .route("/:projectId")
  .get(
    validateProjectPermission([
      UserRolesEnum.ADMIN,
      UserRolesEnum.PROJECT_ADMIN,
    ]),
    getProjectById,
  )
  .put(
    createProjectValidator,
    validateProjectPermission([UserRolesEnum.ADMIN]),
    updateProjectById,
  )
  .delete(validateProjectPermission([UserRolesEnum.ADMIN]), deleteProjectById);

router
  .route("/:projectId/members")
  .get(checkToken, getProjectMemberByProjectId)
  .post(
    addMemberToProjectValidator,
    validateProjectPermission([UserRolesEnum.ADMIN]),
    addProjectMemberByProjectId,
  );

router
  .route("/:projectId/members/:userId")
  .put(
    validateProjectPermission([UserRolesEnum.ADMIN]),
    updateProjectMemberRoleInfoByProjectId,
  )
  .delete(
    validateProjectPermission([UserRolesEnum.ADMIN]),
    deleteProjectMemberByProjectId,
  );

export default router;
