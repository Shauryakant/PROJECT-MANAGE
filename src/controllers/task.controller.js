import { ApiResponse } from "../utils/api-response.js";
import { ApiError } from "../utils/api-error.js";
import { asyncHandler } from "../utils/asynchandlers.js";
import mongoose, { isValidObjectId } from "mongoose";
import { Project } from "../models/project.model.js";
import { Projectmember } from "../models/projectmember.model.js";
import { Task } from "../models/task.models.js";
import { Subtask } from "../models/subtask.model.js";

const createTask = asyncHandler(async (req, res) => {
  const { projectId } = req.params;
  const { description, title, memberId } = req.body;
  const member = await Projectmember.findOne({
    user: new mongoose.Types.ObjectId(memberId),
    project: new mongoose.Types.ObjectId(projectId),
  });
  if (!member) {
    throw new ApiError(
      400,
      "Member with this id does not exist or it is not member of Project",
    );
  }
  const files = req.files || [];
  const attachments = files.map((file) => {
    return {
      url: `${process.env.SERVER_URL}/images/${file.filename}`,
      mimetype: file.mimetype,
      size: file.size,
    };
  });
  const task = await Task.create({
    title,
    description,
    project: new mongoose.Types.ObjectId(projectId),
    assignedBy: new mongoose.Types.ObjectId(req.user._id),
    assignedTo: new mongoose.Types.ObjectId(memberId),
    attachments,
  });
  return res
    .status(200)
    .json(
      new ApiResponse(200, task, "Successfully created a task for project"),
    );
});

const getTasks = asyncHandler(async (req, res) => {
  const { projectId } = req.params;
  const fetchedTasks = await Task.aggregate([
    {
      $match: {
        project: new mongoose.Types.ObjectId(projectId),
      },
    },
    {
      $lookup: {
        from: "users",
        localField: "assignedBy",
        foreignField: "_id",
        as: "assignedBy",
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
    { $unwind: "$assignedBy" },
    ,
    {
      $lookup: {
        from: "users",
        localField: "assignedTo",
        foreignField: "_id",
        as: "assignedTo",
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
    { $unwind: "$assignedTo" },
    {
      $project: {
        description: 1,
        title: 1,
        assignedBy: 1,
        assignedTo: 1,
        attachments: 1,
        status: 1,
      },
    },
  ]);
  // aliter
  // const t=await Task.find({
  //   project:new mongoose.Types.ObjectId(projectId)
  // }).populate("assignedTo","username avatar")

  return res
    .status(200)
    .json(
      new ApiResponse(
        200,
        fetchedTasks,
        "Successfully fetched tasks of project",
      ),
    );
});

const getTaskById = asyncHandler(async (req, res) => {
  const { projectId, taskId } = req.params;
  //   const project = await Project.findById({
  //     _id: projectId,
  //   });
  //   if (!project) {
  //     throw new ApiError(404, "Project does not exist");
  //   }
  if (!mongoose.isValidObjectId(taskId)) {
    throw new ApiError(404, "Please enter a valid taskid");
  }
  const task = await Task.aggregate([
    {
      $match: {
        _id: new mongoose.Types.ObjectId(taskId),
      },
    },
    {
      $lookup: {
        from: "subtasks",
        localField: "_id",
        foreignField: "task",
        as: "subtasks",
        pipeline: [
          {
            $lookup: {
              from: "users",
              localField: "createdBy",
              foreignField: "_id",
              as: "createdBy",
            },
          },
          { $unwind: "$createdBy" },
          {
            $addFields: {
              avatar: "$createdBy.avatar",
              createdBy: "$createdBy.username",
            },
          },
          {
            $project: {
              details: 1,
              completed: 1,
              createdBy: 1,
              avatar: 1,
            },
          },
        ],
      },
    },
    {
      $lookup: {
        from: "users",
        localField: "assignedBy",
        foreignField: "_id",
        as: "assignedBy",
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
    { $unwind: "$assignedBy" },
    {
      $lookup: {
        from: "users",
        localField: "assignedTo",
        foreignField: "_id",
        as: "assignedTo",
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
    { $unwind: "$assignedTo" },
    {
      $project: {
        subtasks: 1,
        title: 1,
        description: 1,
        attachments: 1,
        status: 1,
        assignedBy: 1,
        assignedTo: 1,
      },
    },
  ]);
  if(!task || task.length===0) {
    throw new ApiError(400,"Task not found")
  }
  return res
    .status(200)
    .json(
      new ApiResponse(
        200,
        task[0],
        "Successfully fetched the task of the project",
      ),
    );
});

const updateTaskById = asyncHandler(async (req, res) => {
  const { projectId, taskId } = req.params;
  const { title, description, attachments, status, assignedTo } = req.body;
  if (!mongoose.isValidObjectId(taskId)) {
    throw new ApiError(404, "Please enter a valid taskid");
  }
  const task = await Task.findByIdAndUpdate(
    taskId,
    {
      title,
      description,
      attachments,
      status,
      assignedTo,
    },
    { new: true },
  );
  return res
    .status(200)
    .json(new ApiResponse(200, { task }, "Successfully updated the task"));
});

const deleteTaskById = asyncHandler(async (req, res) => {
  const { taskId } = req.params;
  if (!mongoose.isValidObjectId(taskId)) {
    throw new ApiError(404, "Please enter a valid taskid");
  }
  const task = await Project.findByIdAndDelete({
    _id: new mongoose.Types.ObjectId(taskId),
  });
  if (!task) {
    throw new ApiError(
      500,
      "Error while deleting the project, taskId may not exist",
    );
  }
  return res
    .status(200)
    .json(new ApiResponse(200, {}, "Successfully deleted the project"));
});

const createSubtask = asyncHandler(async (req, res) => {
  const { taskId } = req.params;
  //access needed
  const { details } = req.body;
  if (!mongoose.isValidObjectId(taskId)) {
    throw new ApiError(400, "Please enter a valid taskid");
  }
  const subTask = await Subtask.create({
    details,
    createdBy: req.user._id,
    task: taskId,
  });
  return res
    .status(200)
    .json(new ApiResponse(200, { subTask }, "Successfully created subTask"));
});

const updateSubtask = asyncHandler(async (req, res) => {
  const { subTaskId } = req.params;
  //access needed
  const { details, completed } = req.body;
  if (!mongoose.isValidObjectId(subTaskId)) {
    throw new ApiError(400, "Please enter a valid subtask id");
  }
  const subtask = await Subtask.findByIdAndUpdate(subTaskId, {
    details,
    completed,
  });
  return res
    .status(200)
    .json(new ApiResponse(200, { subtask }, "Successfully updated subtask"));
});

const deleteSubtask = asyncHandler(async (req, res) => {
  const { subTaskId } = req.params;
  //access needed
  if (!mongoose.isValidObjectId(subTaskId)) {
    throw new ApiError(400, "Please enter a valid subtask id");
  }
  const subtask = await Subtask.findByIdAndDelete(subTaskId);
  return res
    .status(200)
    .json(new ApiResponse(200, {}, "Successfully deleted subtask"));
});

export {
  getTasks,
  createTask,
  getTaskById,
  updateTaskById,
  deleteTaskById,
  createSubtask,
  updateSubtask,
  deleteSubtask,
};
