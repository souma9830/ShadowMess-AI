import { io } from 'socket.io-client';

const socketUrl = import.meta.env.DEV ? '' : import.meta.env.VITE_SOCKET_URL;

const socket = io(socketUrl, { 
    path: '/socket.io',
    transports: ['websocket', 'polling'], 
    autoConnect: true 
});

export default socket;
