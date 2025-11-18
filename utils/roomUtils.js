import Room from "../models/Room.js";

// Generate unique room code
export const generateUniqueRoomCode = async () => {
  const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  let code;
  let exists = true;

  while (exists) {
    code = "";
    for (let i = 0; i < 6; i++) {
      code += characters.charAt(Math.floor(Math.random() * characters.length));
    }

    const room = await Room.findOne({ code });
    exists = !!room;
  }

  return code;
};

// Check if user has permission
export const hasPermission = (room, username, action) => {
  const user = room.users.find((u) => u.username === username);
  if (!user) return false;

  switch (action) {
    case "kick":
    case "assign-role":
      return user.role === "leader" || user.role === "co-leader";
    case "delete-room":
      return user.role === "leader";
    default:
      return false;
  }
};
