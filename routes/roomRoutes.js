import express from "express";
import Room from "../models/Room.js";
const router = express.Router();

router.post("/join", async (req, res) => {
  const { code, username } = req.body;
  if (!code || !username)
    return res.status(400).json({ msg: "Missing fields" });

  let room = await Room.findOne({ code });
  if (!room) room = await Room.create({ code, users: [username] });
  else if (!room.users.includes(username)) room.users.push(username);

  await room.save();
  res.json({ msg: "Joined", room });
});

export default router;
