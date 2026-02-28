import { ApiResponse } from "../utils/api-response.js";
import { ApiError } from "../utils/api-error.js";
import { asyncHandler } from "../utils/asynchandlers.js";
import mongoose from "mongoose";
import { Project } from "../models/project.model.js";
import { Projectmember } from "../models/projectmember.model.js";
import { UserRolesEnum } from "../utils/constants.js";
import { User } from "../models/user.model.js";

const createProject = asyncHandler(async (req, res) => {
  const { description, name } = req.body;
  const project = await Project.create({
    description,
    name,
    createdBy: new mongoose.Types.ObjectId(req.user._id),
  });
  const projectmember = await Projectmember.create({
    user: new mongoose.Types.ObjectId(req.user._id),
    project,
    role: UserRolesEnum.ADMIN,
  });
  if (!project || !projectmember) {
    throw new ApiError(500, "Error while creating new project");
  }
  return res
    .status(200)
    .json(new ApiResponse(200, project, "Successfully created a project"));
});

const getProjects = asyncHandler(async (req, res) => {
  const fetchedProjects = await Projectmember.aggregate([
    {
      $match: {
        user: new mongoose.Types.ObjectId(req.user._id),
      },
    },
    {
      $lookup: {
        from: "projects",
        localField: "project",
        foreignField: "_id",
        as: "projectInfo",
        pipeline: [
          {
            $lookup: {
              from: "projectmembers",
              localField: "_id",
              foreignField: "project",
              as: "numberOfMembers",
              pipeline: [
                {
                  $count: "members",
                },
              ],
            },
          },
          {
            $addFields: {
              members: {
                $ifNull: [{ $arrayElemAt: ["$numberOfMembers.members", 0] }, 0],
              },
            },
          },
          {
            $project: {
              members: 1,
              description: 1,
              name: 1,
            },
          },
        ],
      },
    },
    { $unwind: "$projectInfo" },
    {
      $addFields: {
        members: "$projectInfo.members",
        description: "$projectInfo.description",
        name: "$projectInfo.name",
      },
    },
    {
      $project: {
        description: 1,
        name: 1,
        members: 1,
        _id: 1,
      },
    },
  ]);
  // if (fetchedProjects.length === 0) {
  //   throw new ApiError(
  //     500,
  //     "Error while fetching projects or user has no projects",
  //   );
  // }
  return res
    .status(200)
    .json(
      new ApiResponse(
        200,
        fetchedProjects,
        "Successfully fetched projects of user",
      ),
    );
});

const getProjectById = asyncHandler(async (req, res) => {
  const { projectId } = req.params;
  // const eligibleUser = await Projectmember.findOne({
  //   project: projectId,
  //   user: req.user._id,
  //   role: UserRolesEnum.ADMIN || UserRolesEnum.PROJECT_ADMIN,
  // });
  // if (!eligibleUser) {
  //   throw new ApiError(400, "User is not authorized to get project info");
  // }
  const project = await Project.findById({
    _id: projectId,
  });
  if (!project) {
    throw new ApiError(500, "Error while finding the project");
  }
  return res
    .status(200)
    .json(new ApiResponse(200, project, "Successfully fetched the project"));
});

const updateProjectById = asyncHandler(async (req, res) => {
  const { projectId } = req.params;
  const { name, description } = req.body;
  const project = await Project.findByIdAndUpdate(
    projectId,
    {
      description,
      name,
    },
    { new: true },
  );
  if (!project) {
    throw new ApiError(500, "Error while updating project ");
  }
  return res
    .status(200)
    .json(
      new ApiResponse(200, { project }, "Successfully updated the project"),
    );
});

const deleteProjectById = asyncHandler(async (req, res) => {
  const { projectId } = req.params;

  const project = await Project.findByIdAndDelete({
    _id: projectId,
  });
  if (!project) {
    throw new ApiError(500, "Error while deleting the project");
  }
  return res
    .status(200)
    .json(new ApiResponse(200, {}, "Successfully deleted the project"));
});

const getProjectMemberByProjectId = asyncHandler(async (req, res) => {
  const { projectId } = req.params;
  //access needed
  const project = await Project.findById(projectId);
  if (!project) {
    throw new ApiError(404, "No project found with such id");
  }
  const projectmembers = await Projectmember.aggregate([
    {
      $match: {
        project: new mongoose.Types.ObjectId(projectId),
      },
    },
    {
      $lookup: {
        from: "users",
        localField: "user",
        foreignField: "_id",
        as: "userInfo",
        pipeline: [
          {
            $project: {
              username: 1,
              avatar: 1,
            },
          },
        ],
      },
    },
    {
      $unwind: "$userInfo",
    },
    {
      $project: {
        role: 1,
        username: "$userInfo.username",
        avatar: "$userInfo.avatar",
      },
    },
  ]);

  return res
    .status(200)
    .json(
      new ApiResponse(
        200,
        projectmembers,
        "Successfully fetched the project members",
      ),
    );
});

const addProjectMemberByProjectId = asyncHandler(async (req, res) => {
  const { projectId } = req.params;
  const { email, role } = req.body;

  const checkUser = await User.findOne({ email });
  if (!checkUser) {
    throw new ApiError(404, "User with this email not found");
  }
  const ifExistingMember = await Projectmember.findOne({
    user: new mongoose.Types.ObjectId(checkUser._id),
    project: new mongoose.Types.ObjectId(projectId),
  });
  if (ifExistingMember) {
    throw new ApiError(404, "User with this email already on project");
  }
  const projectmember = await Projectmember.create({
    user: new mongoose.Types.ObjectId(checkUser._id),
    project: new mongoose.Types.ObjectId(projectId),
    assignedBy: new mongoose.Types.ObjectId(req.user._id),
    role,
  });
  if (!projectmember) {
    throw new ApiError(500, "Error while addding member to the project");
  }
  return res
    .status(200)
    .json(
      new ApiResponse(
        200,
        { projectmember },
        "Successfully added the member to project",
      ),
    );
});

const updateProjectMemberRoleInfoByProjectId = asyncHandler(
  async (req, res) => {
    const { projectId, userId } = req.params;
    const { role } = req.body;

    // check existemce of projectid and userId
    const checkProjectmember = await Projectmember.findOne({
      project: new mongoose.Types.ObjectId(projectId),
      user: new mongoose.Types.ObjectId(userId),
    });
    if (!checkProjectmember) {
      throw new ApiError(400, "Project member not found ");
    }

    checkProjectmember.role = role;
    await checkProjectmember.save({ validateBeforeSave: true });
    return res
      .status(200)
      .json(
        new ApiResponse(
          200,
          { eligibleMember },
          "Successfully updated member role in project",
        ),
      );
  },
);

const deleteProjectMemberByProjectId = asyncHandler(async (req, res) => {
  const { projectId, userId } = req.params;

  const eligibleMember = await Projectmember.findOne({
    project: new mongoose.Types.ObjectId(projectId),
    user: new mongoose.Types.ObjectId(userId),
  });
  if (!eligibleMember) {
    throw new ApiError(400, "User with given id and project id is not found ");
  }
  const deletedMember = await Projectmember.findByIdAndDelete(
    eligibleMember._id,
  );
  if (!deletedMember) {
    throw new ApiError(500, "User with given id and project id is not found ");
  }
  return res
    .status(200)
    .json(
      new ApiResponse(200, {}, "Successfully deleted member role in project"),
    );
});

export {
  createProject,
  deleteProjectById,
  updateProjectById,
  getProjectById,
  getProjectMemberByProjectId,
  getProjects,
  addProjectMemberByProjectId,
  updateProjectMemberRoleInfoByProjectId,
  deleteProjectMemberByProjectId,
};
