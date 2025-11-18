import mongoose from "mongoose";

const roomSchema = new mongoose.Schema({
  code: { type: String, required: true, unique: true },
  users: [
    {
      username: String,
      role: {
        type: String,
        enum: ["leader", "co-leader", "member"],
        default: "member",
      },
      joinedAt: { type: Date, default: Date.now },
    },
  ],
  isPersistent: { type: Boolean, default: false },
  persistenceDays: { type: Number, default: 7 },
  createdAt: { type: Date, default: Date.now },
  createdBy: String,
  maxUsers: { type: Number, default: 50 },
});

export default mongoose.model("Room", roomSchema);
