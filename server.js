import express from "express";
import { createServer } from "http";
import { Server } from "socket.io";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import validator from "validator";
import AWS from "aws-sdk";
import connectDB from "./config/db.js";
import dotenv from "dotenv";
import Room from "./models/Room.js";
import Message from "./models/Message.js";

// Import routes
import roomRoutes from "./routes/roomRoutes.js";
import exportRoutes from "./routes/exportRoutes.js";

// Initialize dotenv to load .env file
dotenv.config();

const app = express();

// AWS S3 Configuration
const s3 = new AWS.S3({
  accessKeyId: process.env.AWS_ACCESS_KEY_ID,
  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  region: process.env.AWS_REGION || "ap-south-1",
});

// Connect to MongoDB
connectDB();

// ========== MIDDLEWARE SETUP ==========
// Body parsing middleware - MUST COME FIRST
app.use(express.json({ limit: "10kb" }));
app.use(express.urlencoded({ extended: true, limit: "10kb" }));

// CORS configuration
app.use(
  cors({
    origin: (origin, callback) => {
      const allowedOrigins = [
        process.env.CLIENT_URL || "http://localhost:5173",
        "https://private-frontend-kov9nbd7m-bodapati-sai-praneeths-projects.vercel.app",
        "https://securechat1335.vercel.app",
        "https://private-backend-k0py.onrender.com",
      ];
      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error("Not allowed by CORS"));
      }
    },
    credentials: true,
  })
);

// Security middleware
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        scriptSrc: ["'self'"],
        connectSrc: [
          "'self'",
          "ws:",
          "wss:",
          process.env.CLIENT_URL || "http://localhost:5173",
          `https://${process.env.AWS_S3_BUCKET}.s3.${process.env.AWS_REGION}.amazonaws.com`,
        ],
      },
    },
  })
);

// Rate limiting
const limiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000, // 15 minutes
  max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100,
});
app.use(limiter);

// ========== ROUTES ==========
app.use("/api/rooms", roomRoutes);
app.use("/api/export", exportRoutes);

// Health check endpoint
app.get("/health", (req, res) => {
  res.json({
    status: "OK",
    timestamp: new Date().toISOString(),
    serverIP: req.headers["x-forwarded-for"] || req.socket.remoteAddress,
    port: process.env.PORT || 5000,
  });
});

// Server info endpoint
app.get("/info", (req, res) => {
  res.json({
    server: "Secure Chat Server",
    version: "1.0.0",
    ip: req.headers["x-forwarded-for"] || req.socket.remoteAddress,
    port: process.env.PORT || 5000,
  });
});

// Test endpoint to verify body parsing
app.post("/api/test-body", (req, res) => {
  console.log("Test body received:", req.body);
  res.json({ received: req.body });
});

const server = createServer(app);

const io = new Server(server, {
  cors: {
    origin: (origin, callback) => {
      const allowedOrigins = [
        process.env.CLIENT_URL || "http://localhost:5173",
        "https://private-frontend-kov9nbd7m-bodapati-sai-praneeths-projects.vercel.app",
        "https://securechat1335.vercel.app",
        "https://private-backend-k0py.onrender.com",
      ];
      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error("Not allowed by CORS"));
      }
    },
    methods: ["GET", "POST"],
    credentials: true,
  },
});

// In-memory storage for rooms
const rooms = new Map();
const userSessions = new Map();
const messageRateLimits = new Map();
const roomFiles = new Map();

const sanitize = {
  username: (input) => {
    const sanitized = validator.escape(validator.trim(input));
    return sanitized && sanitized.length <= 20 ? sanitized : null;
  },
  roomCode: (input) => {
    const sanitized = validator.escape(validator.trim(input));
    return sanitized && sanitized.length <= 20 ? sanitized : null;
  },
  message: (input) => {
    const sanitized = validator.escape(validator.trim(input));
    return sanitized && sanitized.length <= 1000 ? sanitized : null;
  },
  filename: (input) => {
    const sanitized = validator.escape(input).replace(/[^a-zA-Z0-9.-]/g, "__");
    return sanitized && sanitized.length <= 100 ? sanitized : null;
  },
};

const checkRateLimit = (socketId) => {
  const now = Date.now();
  const windowMs = parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000;
  const maxMessages = parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100;

  if (!messageRateLimits.has(socketId)) {
    messageRateLimits.set(socketId, []);
  }

  const timestamps = messageRateLimits.get(socketId);
  const recentTimestamps = timestamps.filter((ts) => now - ts < windowMs);

  if (recentTimestamps.length >= maxMessages) {
    return false;
  }

  recentTimestamps.push(now);
  messageRateLimits.set(socketId, recentTimestamps);

  return true;
};

// Cleanup function for expired data
const cleanupExpiredData = async () => {
  try {
    const expiredMessages = await Message.deleteMany({
      expiresAt: { $lt: new Date() },
    });

    if (expiredMessages.deletedCount > 0) {
      console.log(
        `Cleaned up ${expiredMessages.deletedCount} expired messages`
      );
    }

    const emptyRooms = await Room.deleteMany({
      "users.0": { $exists: false },
      isPersistent: false,
    });

    if (emptyRooms.deletedCount > 0) {
      console.log(`Cleaned up ${emptyRooms.deletedCount} empty rooms`);
    }
  } catch (error) {
    console.error("Cleanup error:", error);
  }
};

setInterval(cleanupExpiredData, 60 * 60 * 1000);

io.on("connection", (socket) => {
  console.log("✅ New connection:", socket.id);

  let currentRoom = null;
  let currentUsername = null;

  socket.on("joinRoom", async ({ username, roomCode }) => {
    try {
      const sanitizedUsername = sanitize.username(username);
      const sanitizedRoomCode = sanitize.roomCode(roomCode);

      console.log("🔗 Join room attempt:", {
        username: sanitizedUsername,
        roomCode: sanitizedRoomCode,
        socketId: socket.id,
      });

      if (!sanitizedUsername || !sanitizedRoomCode) {
        socket.emit("error", "Invalid username or room code");
        return;
      }

      if (userSessions.has(socket.id)) {
        socket.emit("error", "Already in a room");
        return;
      }

      // Check if room exists in database
      let room = await Room.findOne({ code: sanitizedRoomCode });
      if (!room) {
        console.log("❌ Room not found:", sanitizedRoomCode);
        socket.emit("error", "Room not found");
        return;
      }

      console.log(
        "📋 Room found:",
        room.code,
        "Users:",
        room.users.map((u) => ({ username: u.username, role: u.role }))
      );

      // Check if user is in the room
      const userInRoom = room.users.find(
        (u) => u.username === sanitizedUsername
      );
      if (!userInRoom) {
        console.log("❌ User not in room:", sanitizedUsername);
        socket.emit(
          "error",
          "You are not a member of this room. Please join from the home page."
        );
        return;
      }

      // Initialize in-memory room data if not exists
      if (!rooms.has(sanitizedRoomCode)) {
        console.log("🏠 Creating in-memory room:", sanitizedRoomCode);
        rooms.set(sanitizedRoomCode, {
          users: new Map(),
          messages: [],
          lastActivity: Date.now(),
        });
        roomFiles.set(sanitizedRoomCode, new Map());
      }

      const roomData = rooms.get(sanitizedRoomCode);

      if (roomData.users.size >= room.maxUsers) {
        socket.emit("error", "Room is full (max 50 users)");
        return;
      }

      // Add user to room
      roomData.users.set(socket.id, sanitizedUsername);
      userSessions.set(socket.id, {
        username: sanitizedUsername,
        roomCode: sanitizedRoomCode,
      });

      currentRoom = sanitizedRoomCode;
      currentUsername = sanitizedUsername;

      socket.join(sanitizedRoomCode);

      // Load messages from database
      const messageQuery = room.isPersistent
        ? { roomCode: sanitizedRoomCode }
        : {
            roomCode: sanitizedRoomCode,
            $or: [
              { expiresAt: { $exists: false } },
              { expiresAt: { $gt: new Date() } },
            ],
          };

      const dbMessages = await Message.find(messageQuery)
        .sort({ createdAt: 1 })
        .limit(1000);

      console.log("💾 Loaded messages from DB:", dbMessages.length);

      // Convert to frontend format
      const formattedMessages = dbMessages.map((msg) => ({
        id: msg._id.toString(),
        username: msg.user,
        content: msg.text,
        timestamp: msg.createdAt.toISOString(),
        type: msg.type || "user",
        fileUrl: msg.fileUrl,
        fileName: msg.fileName,
        fileSize: msg.fileSize,
      }));

      roomData.messages = formattedMessages;

      // Send room info to user
      const roomInfo = {
        isPersistent: room.isPersistent,
        persistenceDays: room.persistenceDays,
        userRole: userInRoom.role,
        createdBy: room.createdBy,
      };

      console.log("📤 Sending room info:", roomInfo);
      socket.emit("roomInfo", roomInfo);

      socket.emit("loadMessages", roomData.messages);

      // Update room users for everyone
      io.to(sanitizedRoomCode).emit(
        "roomUsers",
        Array.from(roomData.users.values())
      );

      console.log(
        "👥 Room users after join:",
        Array.from(roomData.users.values())
      );

      const systemMessage = {
        id: Date.now().toString(),
        type: "system",
        content: `${sanitizedUsername} joined the room`,
        timestamp: new Date().toISOString(),
      };

      roomData.messages.push(systemMessage);

      // Save system message to database
      const systemMsgDoc = new Message({
        roomCode: sanitizedRoomCode,
        user: "System",
        text: `${sanitizedUsername} joined the room`,
        type: "system",
        expiresAt: room.isPersistent
          ? undefined
          : new Date(Date.now() + room.persistenceDays * 24 * 60 * 60 * 1000),
      });
      await systemMsgDoc.save();

      io.to(sanitizedRoomCode).emit("systemMessage", systemMessage);

      console.log(
        `✅ ${sanitizedUsername} successfully joined room ${sanitizedRoomCode} as ${userInRoom.role}`
      );
    } catch (error) {
      console.error("❌ Join room error:", error);
      socket.emit("error", "Failed to join room: " + error.message);
    }
  });

  socket.on("requestUploadUrl", ({ filename, fileType }) => {
    if (!currentRoom || !currentUsername) {
      socket.emit("error", "Not in a room");
      return;
    }

    const sanitizedFilename = sanitize.filename(filename);
    if (!sanitizedFilename) {
      socket.emit("error", "Invalid filename");
      return;
    }

    const key = `rooms/${currentRoom}/${Date.now()}-${sanitizedFilename}`;
    const params = {
      Bucket: process.env.AWS_S3_BUCKET,
      Key: key,
      ContentType: fileType || "application/octet-stream",
      Expires: 3600,
      ACL: "private",
    };

    try {
      const presignedUrl = s3.getSignedUrl("putObject", params);
      const fileUrl = `https://${process.env.AWS_S3_BUCKET}.s3.${process.env.AWS_REGION}.amazonaws.com/${key}`;

      roomFiles.get(currentRoom).set(key, socket.id);

      socket.emit("uploadUrl", { presignedUrl, fileUrl, key });
      console.log(
        `📎 Presigned URL generated for ${sanitizedFilename} in room ${currentRoom}`
      );
    } catch (error) {
      console.error("Presigned URL error:", error);
      socket.emit("error", "Failed to generate upload URL");
    }
  });

  socket.on("fileUploaded", async ({ fileUrl, filename, key, extension }) => {
    if (!currentRoom || !currentUsername) {
      socket.emit("error", "Not in a room");
      return;
    }

    const message = {
      id: Date.now().toString(),
      username: currentUsername,
      content: `${filename} (${fileUrl})`,
      timestamp: new Date().toISOString(),
      type: "file",
      fileKey: key,
      uploaderSocketId: socket.id,
      fileName: filename,
      fileUrl: fileUrl,
    };

    const roomData = rooms.get(currentRoom);
    if (roomData) {
      roomData.messages.push(message);
      io.to(currentRoom).emit("message", message);
    }

    // Save file message to database
    try {
      const room = await Room.findOne({ code: currentRoom });
      const fileMsgDoc = new Message({
        roomCode: currentRoom,
        user: currentUsername,
        text: `${filename} (${fileUrl})`,
        type: "file",
        fileUrl: fileUrl,
        fileName: filename,
        expiresAt: room.isPersistent
          ? undefined
          : new Date(Date.now() + room.persistenceDays * 24 * 60 * 60 * 1000),
      });
      await fileMsgDoc.save();
    } catch (error) {
      console.error("Failed to save file message to database:", error);
    }
  });

  socket.on("requestDownloadUrl", ({ key }) => {
    if (!currentRoom || !currentUsername) {
      socket.emit("error", "Not in a room");
      return;
    }

    const params = {
      Bucket: process.env.AWS_S3_BUCKET,
      Key: key,
      Expires: 3600,
    };

    try {
      const downloadUrl = s3.getSignedUrl("getObject", params);
      socket.emit("downloadUrl", { key, downloadUrl });
      console.log(`📥 Presigned download URL generated for ${key}`);
    } catch (error) {
      console.error("Download URL error:", error);
      socket.emit("error", "Failed to generate download URL");
    }
  });

  socket.on("deleteFile", ({ key }) => {
    if (!currentRoom || !currentUsername) {
      socket.emit("error", "Not in a room");
      return;
    }

    const fileMap = roomFiles.get(currentRoom);
    if (!fileMap.has(key) || fileMap.get(key) !== socket.id) {
      socket.emit("error", "Not authorized to delete this file");
      return;
    }

    const params = {
      Bucket: process.env.AWS_S3_BUCKET,
      Key: key,
    };

    s3.deleteObject(params, (err) => {
      if (err) {
        console.error(`File deletion error: ${key}`, err);
        socket.emit("error", "Failed to delete file");
        return;
      }
      fileMap.delete(key);
      const systemMessage = {
        id: Date.now().toString(),
        type: "system",
        content: `${currentUsername} deleted a file`,
        timestamp: new Date().toISOString(),
      };
      const roomData = rooms.get(currentRoom);
      roomData.messages.push(systemMessage);
      io.to(currentRoom).emit("systemMessage", systemMessage);
      io.to(currentRoom).emit("fileDeleted", { key });
      console.log(`🗑️ File deleted: ${key} by ${currentUsername}`);
    });
  });

  socket.on("kickUser", async ({ targetUsername }) => {
    try {
      if (!currentRoom || !currentUsername) {
        socket.emit("error", "Not in a room");
        return;
      }

      console.log(
        `🚫 Kick attempt: ${currentUsername} trying to kick ${targetUsername} from ${currentRoom}`
      );

      const room = await Room.findOne({ code: currentRoom });
      if (!room) {
        socket.emit("error", "Room not found");
        return;
      }

      // Check if user has permission to kick
      const user = room.users.find((u) => u.username === currentUsername);
      if (!user || (user.role !== "leader" && user.role !== "co-leader")) {
        socket.emit("error", "Insufficient permissions");
        return;
      }

      // Cannot kick yourself
      if (currentUsername === targetUsername) {
        socket.emit("error", "Cannot kick yourself");
        return;
      }

      // Check if target user exists in room
      const targetUser = room.users.find((u) => u.username === targetUsername);
      if (!targetUser) {
        socket.emit("error", "User not found in room");
        return;
      }

      // Remove user from database
      room.users = room.users.filter((u) => u.username !== targetUsername);
      await room.save();

      console.log(`✅ User removed from database: ${targetUsername}`);

      // Find socket ID of kicked user and disconnect them
      const roomData = rooms.get(currentRoom);
      if (roomData) {
        let targetSocketId = null;
        for (let [socketId, username] of roomData.users) {
          if (username === targetUsername) {
            targetSocketId = socketId;
            break;
          }
        }

        if (targetSocketId) {
          // Notify the kicked user
          io.to(targetSocketId).emit(
            "kicked",
            "You have been kicked from the room by " + currentUsername
          );

          // Remove from in-memory storage
          roomData.users.delete(targetSocketId);
          userSessions.delete(targetSocketId);

          // Disconnect the socket
          io.to(targetSocketId).disconnectSockets(true);

          console.log(
            `✅ User disconnected and removed from room: ${targetUsername}`
          );
        }
      }

      // Notify room
      const systemMessage = {
        id: Date.now().toString(),
        type: "system",
        content: `${targetUsername} was kicked from the room by ${currentUsername}`,
        timestamp: new Date().toISOString(),
      };

      roomData.messages.push(systemMessage);

      // Save system message to database
      const systemMsgDoc = new Message({
        roomCode: currentRoom,
        user: "System",
        text: `${targetUsername} was kicked from the room by ${currentUsername}`,
        type: "system",
      });
      await systemMsgDoc.save();

      // Update all users in the room
      io.to(currentRoom).emit("systemMessage", systemMessage);
      io.to(currentRoom).emit("roomUsers", Array.from(roomData.users.values()));
      io.to(currentRoom).emit("userKicked", { username: targetUsername });

      console.log(
        `✅ ${targetUsername} kicked from room ${currentRoom} by ${currentUsername}`
      );
    } catch (error) {
      console.error("❌ Kick user error:", error);
      socket.emit("error", "Failed to kick user: " + error.message);
    }
  });

  socket.on("assignRole", async ({ targetUsername, newRole }) => {
    try {
      if (!currentRoom || !currentUsername) {
        socket.emit("error", "Not in a room");
        return;
      }

      console.log(
        `⭐ Role assignment: ${currentUsername} trying to assign ${newRole} to ${targetUsername}`
      );

      const room = await Room.findOne({ code: currentRoom });
      if (!room) {
        socket.emit("error", "Room not found");
        return;
      }

      // Only leader can assign roles
      const user = room.users.find((u) => u.username === currentUsername);
      if (!user || user.role !== "leader") {
        socket.emit("error", "Only room leader can assign roles");
        return;
      }

      // Check if target user exists
      const targetUser = room.users.find((u) => u.username === targetUsername);
      if (!targetUser) {
        socket.emit("error", "User not found in room");
        return;
      }

      // Cannot change your own role through this endpoint
      if (currentUsername === targetUsername) {
        socket.emit("error", "Cannot change your own role");
        return;
      }

      // Update role in database
      targetUser.role = newRole;
      await room.save();

      console.log(
        `✅ Role updated in database: ${targetUsername} is now ${newRole}`
      );

      // Notify room
      const systemMessage = {
        id: Date.now().toString(),
        type: "system",
        content: `${targetUsername} is now ${newRole}`,
        timestamp: new Date().toISOString(),
      };

      const roomData = rooms.get(currentRoom);
      if (roomData) {
        roomData.messages.push(systemMessage);

        // Save system message to database
        const systemMsgDoc = new Message({
          roomCode: currentRoom,
          user: "System",
          text: `${targetUsername} is now ${newRole}`,
          type: "system",
        });
        await systemMsgDoc.save();

        io.to(currentRoom).emit("systemMessage", systemMessage);
      }

      // Find and notify the user whose role changed
      let targetSocketId = null;
      for (let [socketId, username] of roomData.users) {
        if (username === targetUsername) {
          targetSocketId = socketId;
          break;
        }
      }

      if (targetSocketId) {
        io.to(targetSocketId).emit("roleAssigned", {
          targetUsername,
          newRole,
          message: `You are now ${newRole}`,
        });
      }

      // Update room users list for everyone
      io.to(currentRoom).emit("roomUsers", Array.from(roomData.users.values()));

      // Also notify the user who made the change
      socket.emit("roleAssigned", {
        targetUsername,
        newRole,
        message: `${targetUsername} is now ${newRole}`,
      });

      console.log(
        `✅ ${targetUsername} role changed to ${newRole} by ${currentUsername}`
      );
    } catch (error) {
      console.error("❌ Assign role error:", error);
      socket.emit("error", "Failed to assign role: " + error.message);
    }
  });

  socket.on("sendMessage", async (messageContent) => {
    try {
      if (!currentRoom || !currentUsername) {
        socket.emit("error", "Not in a room");
        return;
      }

      if (!checkRateLimit(socket.id)) {
        socket.emit("error", "Message rate limit exceeded");
        return;
      }

      const sanitizedMessage = sanitize.message(messageContent);
      if (!sanitizedMessage) {
        socket.emit("error", "Invalid message");
        return;
      }

      const roomData = rooms.get(currentRoom);
      if (!roomData || !roomData.users.has(socket.id)) {
        socket.emit("error", "Not authorized");
        return;
      }

      const message = {
        id: Date.now().toString(),
        username: currentUsername,
        content: sanitizedMessage,
        timestamp: new Date().toISOString(),
        type: "user",
      };

      roomData.messages.push(message);
      roomData.lastActivity = Date.now();

      // Save message to database
      try {
        const room = await Room.findOne({ code: currentRoom });
        const messageDoc = new Message({
          roomCode: currentRoom,
          user: currentUsername,
          text: sanitizedMessage,
          type: "user",
          expiresAt: room.isPersistent
            ? undefined
            : new Date(Date.now() + room.persistenceDays * 24 * 60 * 60 * 1000),
        });
        await messageDoc.save();
      } catch (error) {
        console.error("Failed to save message to database:", error);
      }

      io.to(currentRoom).emit("message", message);
    } catch (error) {
      console.error("Send message error:", error);
      socket.emit("error", "Failed to send message");
    }
  });

  socket.on("typingStart", () => {
    if (currentRoom && currentUsername) {
      socket.to(currentRoom).emit("userTyping", currentUsername);
    }
  });

  socket.on("typingStop", () => {
    if (currentRoom) {
      socket.to(currentRoom).emit("userStoppedTyping", currentUsername);
    }
  });

  socket.on("leaveRoom", async () => {
    if (currentRoom && currentUsername) {
      const roomData = rooms.get(currentRoom);
      if (roomData) {
        roomData.users.delete(socket.id);

        const systemMessage = {
          id: Date.now().toString(),
          type: "system",
          content: `${currentUsername} left the room`,
          timestamp: new Date().toISOString(),
        };

        roomData.messages.push(systemMessage);

        const systemMsgDoc = new Message({
          roomCode: currentRoom,
          user: "System",
          text: `${currentUsername} left the room`,
          type: "system",
        });
        await systemMsgDoc.save();

        io.to(currentRoom).emit("systemMessage", systemMessage);
        io.to(currentRoom).emit(
          "roomUsers",
          Array.from(roomData.users.values())
        );

        console.log(
          `❌ ${currentUsername} left room ${currentRoom}. Remaining users: ${roomData.users.size}`
        );

        if (roomData.users.size === 0) {
          try {
            const room = await Room.findOne({ code: currentRoom });
            if (room && !room.isPersistent) {
              const files = roomFiles.get(currentRoom);
              if (files && files.size > 0) {
                files.forEach((uploaderId, key) => {
                  s3.deleteObject(
                    { Bucket: process.env.AWS_S3_BUCKET, Key: key },
                    (err) => {
                      if (err)
                        console.error(`File deletion error: ${key}`, err);
                      else console.log(`☑ Deleted file: ${key}`);
                    }
                  );
                });
              }
              roomFiles.delete(currentRoom);
            }
          } catch (error) {
            console.error("Error during room cleanup:", error);
          }

          rooms.delete(currentRoom);
          console.log(`✔ Room ${currentRoom} deleted (no users)`);
        }
      }

      userSessions.delete(socket.id);
      messageRateLimits.delete(socket.id);
    }
  });

  socket.on("disconnect", async (reason) => {
    console.log("❌ User disconnected:", socket.id, "Reason:", reason);

    if (currentRoom && currentUsername) {
      const roomData = rooms.get(currentRoom);
      if (roomData) {
        roomData.users.delete(socket.id);

        const systemMessage = {
          id: Date.now().toString(),
          type: "system",
          content: `${currentUsername} left the room`,
          timestamp: new Date().toISOString(),
        };

        roomData.messages.push(systemMessage);

        try {
          const systemMsgDoc = new Message({
            roomCode: currentRoom,
            user: "System",
            text: `${currentUsername} left the room`,
            type: "system",
          });
          await systemMsgDoc.save();
        } catch (error) {
          console.error("Failed to save disconnect message:", error);
        }

        io.to(currentRoom).emit("systemMessage", systemMessage);
        io.to(currentRoom).emit(
          "roomUsers",
          Array.from(roomData.users.values())
        );

        console.log(
          `❌ ${currentUsername} left room ${currentRoom}. Remaining users: ${roomData.users.size}`
        );

        if (roomData.users.size === 0) {
          try {
            const room = await Room.findOne({ code: currentRoom });
            if (room && !room.isPersistent) {
              const files = roomFiles.get(currentRoom);
              if (files && files.size > 0) {
                files.forEach((uploaderId, key) => {
                  s3.deleteObject(
                    { Bucket: process.env.AWS_S3_BUCKET, Key: key },
                    (err) => {
                      if (err)
                        console.error(`File deletion error: ${key}`, err);
                      else console.log(`☑ Deleted file: ${key}`);
                    }
                  );
                });
              }
              roomFiles.delete(currentRoom);
            }
          } catch (error) {
            console.error("Error during room cleanup:", error);
          }

          rooms.delete(currentRoom);
          console.log(`✔ Room ${currentRoom} deleted (no users)`);
        }
      }

      userSessions.delete(socket.id);
      messageRateLimits.delete(socket.id);
    }
  });
});

const PORT = process.env.PORT || 5000;
server.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));

// Handle graceful shutdown
process.on("SIGINT", () => {
  console.log("\n💡 Shutting down server gracefully...");
  server.close(() => {
    console.log("✅ Server closed");
    process.exit(0);
  });
});

process.on("SIGTERM", () => {
  console.log("\n💡 Shutting down server gracefully...");
  server.close(() => {
    console.log("✅ Server closed");
    process.exit(0);
  });
});
