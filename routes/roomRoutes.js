import express from "express";
import Room from "../models/Room.js";
import { generateUniqueRoomCode, hasPermission } from "../utils/roomUtils.js";

const router = express.Router();

// Create or join room
router.post("/join", async (req, res) => {
  try {
    console.log("📥 Room join request received:", req.body);

    // Check if body exists
    if (!req.body) {
      return res.status(400).json({ msg: "Request body is required" });
    }

    const {
      code,
      username,
      createNew = false,
      isPersistent = false,
      persistenceDays = 7,
    } = req.body;

    if (!username) {
      return res.status(400).json({ msg: "Username is required" });
    }

    let room;

    if (createNew) {
      // Generate unique room code
      const roomCode = await generateUniqueRoomCode();

      room = await Room.create({
        code: roomCode,
        users: [{ username, role: "leader" }],
        isPersistent,
        persistenceDays,
        createdBy: username,
      });

      console.log(
        "✅ New room created:",
        roomCode,
        "Persistent:",
        isPersistent,
        "Days:",
        persistenceDays
      );
    } else {
      if (!code) {
        return res
          .status(400)
          .json({ msg: "Room code is required to join existing room" });
      }

      room = await Room.findOne({ code });
      if (!room) {
        return res.status(404).json({ msg: "Room not found" });
      }

      // Check if user already in room
      const userExists = room.users.some((u) => u.username === username);
      if (!userExists) {
        if (room.users.length >= room.maxUsers) {
          return res.status(400).json({ msg: "Room is full" });
        }
        room.users.push({ username, role: "member" });
        await room.save();
        console.log("✅ User added to room:", username);
      } else {
        console.log("ℹ️ User already in room:", username);
      }
    }

    const userRole = room.users.find((u) => u.username === username).role;
    console.log("👤 User role:", userRole);

    res.json({
      msg: createNew ? "Room created" : "Joined room",
      room,
      userRole: userRole,
    });
  } catch (error) {
    console.error("❌ Room join error:", error);
    res.status(500).json({ msg: "Server error: " + error.message });
  }
});

// Room management routes
router.post("/:code/kick", async (req, res) => {
  try {
    const { code } = req.params;
    const { username, targetUsername } = req.body;

    if (!username || !targetUsername) {
      return res
        .status(400)
        .json({ msg: "Username and targetUsername are required" });
    }

    const room = await Room.findOne({ code });
    if (!room) {
      return res.status(404).json({ msg: "Room not found" });
    }

    // Check permissions
    const user = room.users.find((u) => u.username === username);
    if (!user || (user.role !== "leader" && user.role !== "co-leader")) {
      return res.status(403).json({ msg: "Insufficient permissions" });
    }

    // Remove user from room
    room.users = room.users.filter((u) => u.username !== targetUsername);
    await room.save();

    res.json({ msg: "User kicked successfully" });
  } catch (error) {
    console.error("Kick user error:", error);
    res.status(500).json({ msg: "Server error" });
  }
});

router.post("/:code/role", async (req, res) => {
  try {
    const { code } = req.params;
    const { username, targetUsername, newRole } = req.body;

    if (!username || !targetUsername || !newRole) {
      return res
        .status(400)
        .json({ msg: "Username, targetUsername, and newRole are required" });
    }

    const room = await Room.findOne({ code });
    if (!room) {
      return res.status(404).json({ msg: "Room not found" });
    }

    // Only leader can assign roles
    const user = room.users.find((u) => u.username === username);
    if (!user || user.role !== "leader") {
      return res.status(403).json({ msg: "Only room leader can assign roles" });
    }

    // Update user role
    const targetUser = room.users.find((u) => u.username === targetUsername);
    if (targetUser) {
      targetUser.role = newRole;
      await room.save();
    }

    res.json({ msg: "Role updated successfully" });
  } catch (error) {
    console.error("Role update error:", error);
    res.status(500).json({ msg: "Server error" });
  }
});

export default router;
