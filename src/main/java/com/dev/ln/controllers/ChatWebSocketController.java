package com.dev.ln.controllers;

import com.dev.ln.utils.MessageType;
import io.quarkus.websockets.next.*;
import jakarta.inject.Inject;

@WebSocket(path = "/chat/{username}")
public class ChatWebSocketController {

    public record ChatMessage(MessageType type, String from, String message) {
    }

    @Inject
    WebSocketConnection connection;

    @OnOpen(broadcast = true)
    public ChatMessage onOpen(){
        return new ChatMessage(MessageType.USER_JOINED, connection.pathParam("username"), null);
    }

    @OnClose
    public void onClose() {
        ChatMessage departure = new ChatMessage(MessageType.USER_LEFT, connection.pathParam("username"), null);
        connection.broadcast().sendTextAndAwait(departure);
    }

    @OnTextMessage(broadcast = true)
    public ChatMessage onMessage(ChatMessage message) {
        return message;
    }

}
