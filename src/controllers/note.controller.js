import { ApiResponse } from "../utils/api-response.js";
import { ApiError } from "../utils/api-error.js";
import { asyncHandler } from "../utils/asynchandlers.js";
import mongoose, { isValidObjectId } from "mongoose";
import { Note } from "../models/note.model.js";

const getNotes = asyncHandler(async (req, res) => {
  const { projectId } = req.params;
  const notes = await Note.find({
    project: new mongoose.Types.ObjectId(projectId),
  })
    .populate("createdBy", "username avatar")
    .select("-project");
  if (!notes) {
    throw new ApiError(404, "No notes exist");
  }
  return res
    .status(200)
    .json(
      new ApiResponse(200, notes, "Successfully fetched notes of the project"),
    );
});
const createNote = asyncHandler(async (req, res) => {
  const { projectId } = req.params;
  const { content } = req.body;
  const note = await Note.create({
    content,
    createdBy: req.user._id,
    project: projectId,
  });
  if (!note) {
    throw new ApiError(500, "Error while genarating note");
  }
  return res
    .status(200)
    .json(new ApiResponse(200, note, "Successfully created note"));
});

const getNoteById = asyncHandler(async (req, res) => {
  const { noteId } = req.params;
  if (!mongoose.isValidObjectId(noteId)) {
    throw new ApiError(400, "Enter a valid note Id");
  }
  const note = await Note.findById(noteId);
  if (!note) {
    throw new ApiError(404, "Note with such id does not exist");
  }
  return res
    .status(200)
    .json(new ApiResponse(200, note, "Successfully fetched note"));
});

const updateNoteById = asyncHandler(async (req, res) => {
  const { noteId } = req.params;
  const { content } = req.body;
  if (!mongoose.isValidObjectId(noteId)) {
    throw new ApiError(401, "Enter a valid note Id");
  }
  const note = await Note.findByIdAndUpdate(
    noteId,
    {
      content,
    },
    {
      new: true,
    },
  );
  if (!note) {
    throw new ApiError(404, "Note with such id does not exist");
  }
  return res
    .status(200)
    .json(new ApiResponse(200, note, "Successfully updated note"));
});

const deleteNoteById = asyncHandler(async (req, res) => {
  const { noteId } = req.params;
  if (!mongoose.isValidObjectId(noteId)) {
    throw new ApiError(401, "Enter a valid note Id");
  }
  const note = await Note.findByIdAndDelete(noteId);
  if (!note) {
    throw new ApiError(404, "Note with such id does not exist");
  }
  return res
    .status(200)
    .json(new ApiResponse(200, note, "Successfully deleted note"));
});

export { getNotes, createNote, getNoteById, updateNoteById, deleteNoteById };
