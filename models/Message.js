import mongoose from "mongoose";

const messageSchema = new mongoose.Schema({
  roomCode: String,
  user: String,
  text: String,
  type: { type: String, enum: ["user", "system", "file"], default: "user" },
  fileUrl: String,
  fileName: String,
  fileSize: String,
  createdAt: { type: Date, default: Date.now },
  expiresAt: Date, // For persistent rooms
});

// TTL index for auto-deletion in non-persistent rooms
messageSchema.index(
  { createdAt: 1 },
  {
    expireAfterSeconds: 604800, // 7 days default
    partialFilterExpression: { expiresAt: { $exists: false } },
  }
);

export default mongoose.model("Message", messageSchema);
