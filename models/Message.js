import mongoose from "mongoose";
const messageSchema = new mongoose.Schema({
  roomCode: String,
  user: String,
  text: String,
  createdAt: { type: Date, default: Date.now },
});
export default mongoose.model("Message", messageSchema);
