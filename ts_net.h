/**
 * @file ts_net.h
 * @brief Single-header, Vulkan-flavored networking library built on Winsock2.
 *
 * @author Charles 'xtrium' Riffaud-Declercq
 * @license CC BY-SA 4.0 — https://creativecommons.org/licenses/by-sa/4.0/
 *
 * Usage:
 *   Define TS_NET_IMPLEMENTATION in exactly one translation unit before including this header.
 *   INCLUDE THIS FILE BEFORE ANYTHING ELSE THAT INCLUDE WINDOWS.H !
 *   Note: Uses a pragma to link against Ws2_32.lib.
 *
 * Example (TCP server):
 * @code
 *   #define TS_NET_IMPLEMENTATION
 *   #include <ts/ts_net.h>
 *
 *   ts::net::Context ctx;
 *   ts::Fence        ready {};
 *
 *   ts::net::Socket server = ctx.MakeSocket({
 *       .protocol = ts::net::ENetProtocol::TCP,
 *       .role     = ts::net::ENetRole::Server,
 *       .address  = "0.0.0.0",
 *       .port     = 8080,
 *   });
 *
 *   server.Listen({
 *       .onConnection = [](ts::net::Connection conn) {
 *           conn.Send("Hello!\n");
 *           std::string msg = conn.Receive();
 *       },
 *       .signalFence = ready,
 *   });
 *
 *   ready.Wait();
 * @endcode
 *
 * Example (TCP client):
 * @code
 *   ts::net::Context ctx;
 *   ts::Fence        done {};
 *
 *   ts::net::Socket client = ctx.MakeSocket({
 *       .protocol = ts::net::ENetProtocol::TCP,
 *       .role     = ts::net::ENetRole::Client,
 *       .address  = "127.0.0.1",
 *       .port     = 8080,
 *   });
 *
 *   client.Connect({
 *       .onConnected = [](ts::net::Connection conn) {
 *           std::string reply = conn.Receive();
 *           conn.Send("Goodbye!\n");
 *       },
 *       .signalFence = done,
 *   });
 *
 *   done.Wait();
 * @endcode
 */

#ifndef TS_NET_H
#define TS_NET_H

#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#  define WIN32_EXTRA_LEAN
#endif
#ifndef NOMINMAX
#  define NOMINMAX
#endif
 // Block winsock v1 before windows.h can drag it in,
 // even if windows.h was already included before us.
#ifndef _WINSOCKAPI_
#  define _WINSOCKAPI_
#endif
#include <winsock2.h>
#include <ws2tcpip.h>

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

#include "ts_scheduler.h"

namespace ts
{
    /**
     * @brief Exception thrown on any Winsock error.
     *
     * Carries the WSA error code alongside a human-readable message.
     */
    class NetError
        : public std::runtime_error
    {
    public:
        int code;

        explicit NetError(const std::string& msg, int wsaCode = 0)
            : std::runtime_error(msg + (wsaCode ? " (WSA " + std::to_string(wsaCode) + ")" : ""))
            , code(wsaCode)
        {}
    };

    /** @brief Transport layer protocol selection. */
    enum class ENetProtocol
        : uint8_t
    {
        TCP, ///< Reliable, ordered, connection-oriented stream.
        UDP, ///< Unreliable, connectionless datagram.
    };

    /** @brief Whether the socket acts as server or client. */
    enum class ENetRole
        : uint8_t
    {
        Server, ///< Binds and accepts / receives from any peer.
        Client, ///< Connects to a specific server.
    };

    struct ConnectionInfo;

    /**
     * @brief Represents a live, bidirectional communication channel.
     *
     * For TCP this wraps a connected socket. For UDP this is a thin view over
     * the parent socket plus the remote endpoint. Connections are cheap to copy;
     * they share the underlying descriptor.
     */
    class Connection
    {
        struct State;
        std::shared_ptr<State> m_state;

    public:
        Connection() = default;

        /** @internal Constructed by Socket::Listen / Socket::Connect. */
        explicit Connection(const ConnectionInfo& info);

        /**
         * @brief Sends raw bytes.
         * @param data Byte span to transmit.
         * @throws NetError on send failure.
         */
        void SendRaw(std::span<const std::byte> data);

        /**
         * @brief Sends a string (UTF-8 / ASCII).
         * @throws NetError on send failure.
         */
        void Send(std::string_view text);

        /**
         * @brief Receives up to @p maxBytes bytes (blocks until data arrives).
         * @return Received bytes. Empty vector means the connection was closed.
         * @throws NetError on receive failure.
         */
        [[nodiscard]] std::vector<std::byte> ReceiveRaw(std::size_t maxBytes = 4096);

        /**
         * @brief Receives data as a string (blocks until data arrives).
         * @return Received text. Empty string means the connection was closed.
         * @throws NetError on receive failure.
         */
        [[nodiscard]] std::string Receive(std::size_t maxBytes = 4096);

        /**
         * @brief Returns the remote endpoint address as "ip:port".
         */
        [[nodiscard]] std::string RemoteAddress() const;

        /** @brief Closes the connection gracefully. Safe to call multiple times. */
        void Close();

        /** @brief Returns true if the connection is still open. */
        [[nodiscard]] bool IsOpen() const;
    };

    /**
     * @brief Describes the socket to create via @ref Context::MakeSocket.
     */
    struct SocketInfo
    {
        ENetProtocol    protocol = ENetProtocol::TCP; ///< Transport protocol.
        ENetRole        role     = ENetRole::Client;  ///< Server (bind/listen) or client (connect).
        std::string     address  = "0.0.0.0";         ///< IP address. Server: bind address. Client: target address.
        uint16_t        port     = 0;                 ///< Port number.
        int             backlog  = 64;                ///< TCP server only: listen backlog.
    };

    /**
     * @brief Parameters for @ref Socket::Listen (TCP server).
     *
     * The scheduler accepts incoming connections in a loop; each connection is
     * dispatched asynchronously on its own thread.
     */
    struct ListenInfo
    {
        /** Called on each accepted connection. May be called from any thread. */
        std::function<void(Connection)> onConnection;

        /** If set, signaled once the server begins accepting connections. */
        std::optional<Fence> signalFence;

        /** If set, called when a fatal accept error occurs. */
        std::function<void(const NetError&)> onError;
    };

    /**
     * @brief Parameters for @ref Socket::Connect (TCP client).
     */
    struct ConnectInfo
    {
        /** Called with the established connection. */
        std::function<void(Connection)> onConnected;

        /** Called if the connection attempt fails. */
        std::function<void(const NetError&)> onError;

        /** If set, signaled after @p onConnected returns (or on error). */
        std::optional<Fence> signalFence;
    };

    /**
     * @brief Parameters for @ref Socket::SendTo (UDP, fire-and-forget).
     */
    struct SendToInfo
    {
        std::string              targetAddress;
        uint16_t                 targetPort = 0;
        std::vector<std::byte>   data;

        std::optional<Fence>     signalFence;
    };

    /**
     * @brief Parameters for @ref Socket::ReceiveFrom (UDP server loop).
     */
    struct ReceiveFromInfo
    {
        std::size_t maxDatagramSize = 65507;

        /** Called for each received datagram. @p sender is "ip:port". */
        std::function<void(std::vector<std::byte> data, std::string sender)> onDatagram;

        /** If set, signaled once the socket starts receiving. */
        std::optional<Fence> signalFence;

        std::function<void(const NetError&)> onError;
    };

    /**
     * @brief A network socket with protocol/role-specific operations.
     *
     * Obtained via @ref Context::MakeSocket. Sockets are move-only.
     *
     * @note For TCP servers, @ref Listen spins up an internal thread that
     *       dispatches each accepted connection on its own detached thread.
     *       For UDP, @ref ReceiveFrom starts a receive loop on a detached thread.
     */
    class Socket
    {
        struct State;
        std::shared_ptr<State> m_state;

        explicit Socket(std::shared_ptr<State> state);
        friend class Context;

    public:
        Socket() = default;
        Socket(Socket&&) noexcept = default;
        Socket& operator=(Socket&&) noexcept = default;

        Socket(const Socket&) = delete;
        Socket& operator=(const Socket&) = delete;

        /**
         * @brief TCP server: start accepting connections asynchronously.
         *
         * Spawns a detached listener thread. Each accepted connection is
         * dispatched to @p info.onConnection on its own thread.
         *
         * @throws NetError if the socket is not a TCP server socket.
         */
        void Listen(ListenInfo info);

        /**
         * @brief TCP client: connect to the server asynchronously.
         *
         * Spawns a detached thread that connects and calls @p info.onConnected.
         *
         * @throws NetError if the socket is not a TCP client socket.
         */
        void Connect(ConnectInfo info);

        /**
         * @brief UDP: send a single datagram to the specified endpoint.
         *
         * Fire-and-forget; optionally signals a fence when done.
         *
         * @throws NetError if the socket is not a UDP socket.
         */
        void SendTo(SendToInfo info);

        /**
         * @brief UDP server: start a receive loop asynchronously.
         *
         * Spawns a detached thread that calls @p info.onDatagram for each
         * received packet until @ref Close is called.
         *
         * @throws NetError if the socket is not a UDP socket.
         */
        void ReceiveFrom(ReceiveFromInfo info);

        /** @brief Gracefully closes the socket. Safe to call multiple times. */
        void Close();

        /** @brief Returns true if the socket is open. */
        [[nodiscard]] bool IsOpen() const;

        /** @brief Returns the bound local address as "ip:port" (after Listen/Connect). */
        [[nodiscard]] std::string LocalAddress() const;

        /** @brief Returns the underlying Winsock SOCKET handle. */
        [[nodiscard]] SOCKET Handle() const;
    };

    /**
     * @brief Entry point for ts::net. Manages Winsock lifetime and socket creation.
     *
     * Exactly one Context must be alive while any networking is in use.
     * The Context is non-copyable. Destruction calls WSACleanup.
     *
     * @code
     *   ts::net::Context ctx;
     *   auto sock = ctx.MakeSocket({ .protocol = ts::net::ENetProtocol::TCP, ... });
     * @endcode
     */
    class Context
    {
    public:
        /**
         * @brief Initializes Winsock (WSAStartup).
         * @throws NetError if WSAStartup fails.
         */
        Context();

        /** @brief Calls WSACleanup. */
        ~Context();

        Context(const Context&) = delete;
        Context& operator=(const Context&) = delete;

        /**
         * @brief Creates a configured socket ready for use.
         * @throws NetError on socket creation, bind, or listen failure.
         */
        [[nodiscard]] Socket MakeSocket(SocketInfo info) const;
    };

} // namespace ts::net

#endif // TS_NET_H

#if defined(TS_NET_IMPLEMENTATION) && !defined(TS_NET_BODY_IMPLEMENTED)
#define TS_NET_BODY_IMPLEMENTED

#include <atomic>
#include <thread>

#pragma comment(lib, "Ws2_32.lib")

namespace ts
{
    namespace detail
    {
        static std::string AddrToString(const sockaddr_storage& ss)
        {
            char ip[INET6_ADDRSTRLEN] = {};
            uint16_t port = 0;

            if (ss.ss_family == AF_INET)
            {
                const auto* s4 = reinterpret_cast<const sockaddr_in*>(&ss);
                inet_ntop(AF_INET, &s4->sin_addr, ip, sizeof(ip));
                port = ntohs(s4->sin_port);
            }
            else if (ss.ss_family == AF_INET6)
            {
                const auto* s6 = reinterpret_cast<const sockaddr_in6*>(&ss);
                inet_ntop(AF_INET6, &s6->sin6_addr, ip, sizeof(ip));
                port = ntohs(s6->sin6_port);
            }

            return std::string(ip) + ":" + std::to_string(port);
        }

        static sockaddr_in MakeAddr(const std::string& address, uint16_t port)
        {
            sockaddr_in addr{};
            addr.sin_family = AF_INET;
            addr.sin_port   = htons(port);
            if (inet_pton(AF_INET, address.c_str(), &addr.sin_addr) != 1)
                throw NetError("Invalid address: " + address);
            return addr;
        }

        static void ThrowWsa(const std::string& msg)
        {
            throw NetError(msg, WSAGetLastError());
        }
    }

    // -------------------------------------------------------------------------

    struct Connection::State
    {
        SOCKET            sock       = INVALID_SOCKET;
        std::string       remote;
        bool              isUdp      = false;
        sockaddr_storage  udpPeer    {};
        int               udpPeerLen = 0;
        std::atomic<bool> open       { true };

        State(SOCKET socket, std::string remote)
            : sock(sock)
            , remote(remote)
        {}

        ~State()
        {
            if (sock != INVALID_SOCKET && !isUdp)
                closesocket(sock);
        }
    };

    struct ConnectionInfo
    {
        SOCKET      socket;
        std::string remote;
    };

    Connection::Connection(const ConnectionInfo& info)
        : m_state(std::make_shared<State>(info.socket, info.remote))
    {}

    void Connection::SendRaw(std::span<const std::byte> data)
    {
        if (!m_state || !m_state->open)
            throw NetError("Connection is closed");

        const char* ptr = reinterpret_cast<const char*>(data.data());
        int         rem = static_cast<int>(data.size());

        while (rem > 0)
        {
            int sent;

            if (m_state->isUdp)
            {
                sent = sendto(m_state->sock, ptr, rem, 0,
                    reinterpret_cast<const sockaddr*>(&m_state->udpPeer),
                    m_state->udpPeerLen);
            }
            else
            {
                sent = send(m_state->sock, ptr, rem, 0);
            }

            if (sent == SOCKET_ERROR)
                detail::ThrowWsa("send failed");

            ptr += sent;
            rem -= sent;
        }
    }

    void Connection::Send(std::string_view text)
    {
        SendRaw({ reinterpret_cast<const std::byte*>(text.data()), text.size() });
    }

    std::vector<std::byte> Connection::ReceiveRaw(std::size_t maxBytes)
    {
        if (!m_state || !m_state->open)
            return {};

        std::vector<std::byte> buf(maxBytes);
        int received;

        if (m_state->isUdp)
        {
            int fromLen = sizeof(m_state->udpPeer);
            received = recvfrom(m_state->sock,
                reinterpret_cast<char*>(buf.data()), static_cast<int>(maxBytes), 0,
                reinterpret_cast<sockaddr*>(&m_state->udpPeer), &fromLen);
            m_state->udpPeerLen = fromLen;
        }
        else
        {
            received = recv(m_state->sock,
                reinterpret_cast<char*>(buf.data()), static_cast<int>(maxBytes), 0);
        }

        if (received == 0)
        {
            m_state->open = false;
            return {};
        }
        if (received == SOCKET_ERROR)
        {
            int err = WSAGetLastError();
            if (err == WSAECONNRESET || err == WSAECONNABORTED)
            {
                m_state->open = false;
                return {};
            }
            throw NetError("recv failed", err);
        }

        buf.resize(static_cast<std::size_t>(received));
        return buf;
    }

    std::string Connection::Receive(std::size_t maxBytes)
    {
        auto bytes = ReceiveRaw(maxBytes);
        return { reinterpret_cast<const char*>(bytes.data()), bytes.size() };
    }

    std::string Connection::RemoteAddress() const
    {
        return m_state ? m_state->remote : "";
    }

    void Connection::Close()
    {
        if (m_state && m_state->open.exchange(false))
        {
            if (!m_state->isUdp && m_state->sock != INVALID_SOCKET)
            {
                shutdown(m_state->sock, SD_BOTH);
                closesocket(m_state->sock);
                m_state->sock = INVALID_SOCKET;
            }
        }
    }

    bool Connection::IsOpen() const
    {
        return m_state && m_state->open;
    }

    // -------------------------------------------------------------------------

    struct Socket::State
    {
        SOCKET      sock     = INVALID_SOCKET;
        SocketInfo  info;
        std::atomic<bool> open { false };

        ~State()
        {
            if (sock != INVALID_SOCKET)
                closesocket(sock);
        }
    };

    Socket::Socket(std::shared_ptr<State> state)
        : m_state(std::move(state))
    {}

    void Socket::Listen(ListenInfo info)
    {
        if (!m_state || m_state->info.protocol != ENetProtocol::TCP)
            throw NetError("Listen requires a TCP server socket");
        if (m_state->info.role != ENetRole::Server)
            throw NetError("Listen requires a server-role socket");

        auto state = m_state; // capture shared ownership

        std::thread([state, info = std::move(info)]() mutable
        {
            if (info.signalFence)
                info.signalFence->Signal();

            while (state->open)
            {
                sockaddr_storage clientAddr{};
                int              addrLen = sizeof(clientAddr);

                SOCKET clientSock = accept(state->sock, reinterpret_cast<sockaddr*>(&clientAddr), &addrLen);

                if (clientSock == INVALID_SOCKET)
                {
                    if (!state->open) break; // closed intentionally
                    int err = WSAGetLastError();
                    if (info.onError)
                        info.onError(NetError("accept failed", err));
                    break;
                }

                Connection conn({
                    .socket = clientSock,
                    .remote = detail::AddrToString(clientAddr)
                });

                std::thread([conn, cb = info.onConnection]() mutable
                {
                    if (cb) cb(std::move(conn));
                }).detach();
            }
        }).detach();
    }

    void Socket::Connect(ConnectInfo info)
    {
        if (!m_state || m_state->info.protocol != ENetProtocol::TCP)
            throw NetError("ts_net: Connect requires a TCP socket");
        if (m_state->info.role != ENetRole::Client)
            throw NetError("ts_net: Connect requires a client-role socket");

        auto state = m_state;

        std::thread([state, info = std::move(info)]() mutable
        {
            auto signalDone = [&](const std::optional<NetError>& err)
            {
                if (err && info.onError)
                    info.onError(*err);
                if (info.signalFence)
                    info.signalFence->Signal();
            };

            sockaddr_in addr {};

            try
            {
                addr = detail::MakeAddr(state->info.address, state->info.port);
            }
            catch (const NetError& e)
            {
                signalDone(e);
                return;
            }

            if (connect(state->sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR)
            {
                signalDone(NetError("ts_net: connect failed", WSAGetLastError()));
                return;
            }

            // Retrieve actual remote address for the connection object
            sockaddr_storage remote {};
            int remoteLen = sizeof(remote);
            getpeername(state->sock, reinterpret_cast<sockaddr*>(&remote), &remoteLen);

            Connection conn({
                .socket = state->sock,
                .remote = detail::AddrToString(remote)
            });

            state->sock = INVALID_SOCKET;

            if (info.onConnected)
                info.onConnected(conn);

            signalDone(std::nullopt);
        }).detach();
    }

    void Socket::SendTo(SendToInfo info)
    {
        if (!m_state || m_state->info.protocol != ENetProtocol::UDP)
            throw NetError("ts_net: SendTo requires a UDP socket");

        auto state = m_state;

        std::thread([state, info = std::move(info)]() mutable
        {
            try
            {
                sockaddr_in target = detail::MakeAddr(info.targetAddress, info.targetPort);

                int sent = sendto(state->sock,
                    reinterpret_cast<const char*>(info.data.data()),
                    static_cast<int>(info.data.size()), 0,
                    reinterpret_cast<const sockaddr*>(&target), sizeof(target)
                );

                if (sent == SOCKET_ERROR)
                    detail::ThrowWsa("sendto failed");
            }
            catch (...) {}

            if (info.signalFence)
                info.signalFence->Signal();
        }).detach();
    }

    void Socket::ReceiveFrom(ReceiveFromInfo info)
    {
        if (!m_state || m_state->info.protocol != ENetProtocol::UDP)
            throw NetError("ts_net: ReceiveFrom requires a UDP socket");

        auto state = m_state;

        std::thread([state, info = std::move(info)]() mutable
        {
            if (info.signalFence)
                info.signalFence->Signal();

            while (state->open)
            {
                std::vector<std::byte> buf(info.maxDatagramSize);
                sockaddr_storage       from{};
                int                    fromLen = sizeof(from);

                int received = recvfrom(state->sock,
                    reinterpret_cast<char*>(buf.data()),
                    static_cast<int>(buf.size()), 0,
                    reinterpret_cast<sockaddr*>(&from), &fromLen);

                if (received == SOCKET_ERROR)
                {
                    if (!state->open) break;
                    int err = WSAGetLastError();
                    if (info.onError)
                        info.onError(NetError("recvfrom failed", err));
                    break;
                }

                buf.resize(static_cast<std::size_t>(received));
                std::string sender = detail::AddrToString(from);

                std::thread([buf = std::move(buf), sender, cb = info.onDatagram]() mutable
                {
                    if (cb) cb(std::move(buf), std::move(sender));
                }).detach();
            }
        }).detach();
    }

    void Socket::Close()
    {
        if (m_state && m_state->open.exchange(false))
        {
            if (m_state->sock != INVALID_SOCKET)
            {
                shutdown(m_state->sock, SD_BOTH);
                closesocket(m_state->sock);
                m_state->sock = INVALID_SOCKET;
            }
        }
    }

    bool Socket::IsOpen() const
    {
        return m_state && m_state->open;
    }

    std::string Socket::LocalAddress() const
    {
        if (!m_state || m_state->sock == INVALID_SOCKET)
            return "";

        sockaddr_storage local{};
        int localLen = sizeof(local);
        if (getsockname(m_state->sock, reinterpret_cast<sockaddr*>(&local), &localLen) == 0)
            return detail::AddrToString(local);

        return "";
    }

    SOCKET Socket::Handle() const
    {
        return m_state ? m_state->sock : INVALID_SOCKET;
    }

    // -------------------------------------------------------------------------

    Context::Context()
    {
        WSADATA wsa{};
        int result = WSAStartup(MAKEWORD(2, 2), &wsa);
        if (result != 0)
            throw NetError("WSAStartup failed", result);
    }

    Context::~Context()
    {
        WSACleanup();
    }

    Socket Context::MakeSocket(SocketInfo info) const
    {
        int type    = (info.protocol == ENetProtocol::TCP) ? SOCK_STREAM : SOCK_DGRAM;
        int proto   = (info.protocol == ENetProtocol::TCP) ? IPPROTO_TCP : IPPROTO_UDP;

        SOCKET sock = socket(AF_INET, type, proto);
        if (sock == INVALID_SOCKET)
            detail::ThrowWsa("ts_net: socket creation failed");

        // Allow address reuse for server sockets
        if (info.role == ENetRole::Server)
        {
            int opt = 1;
            setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&opt), sizeof(opt));
        }

        // Bind server sockets (and UDP client sockets need a local port too)
        bool shouldBind = (info.role == ENetRole::Server) || (info.protocol == ENetProtocol::UDP);
        if (shouldBind)
        {
            sockaddr_in addr {};
            try
            {
                addr = detail::MakeAddr(info.address, info.port);
            }
            catch (...)
            {
                closesocket(sock);
                throw;
            }

            if (bind(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR)
            {
                int err = WSAGetLastError();
                closesocket(sock);
                throw NetError("bind failed", err);
            }
        }

        if (info.role == ENetRole::Server && info.protocol == ENetProtocol::TCP)
        {
            if (listen(sock, info.backlog) == SOCKET_ERROR)
            {
                int err = WSAGetLastError();
                closesocket(sock);
                throw NetError("listen failed", err);
            }
        }

        auto state    = std::make_shared<Socket::State>();
        state->sock   = sock;
        state->info   = std::move(info);
        state->open   = true;

        return Socket(std::move(state));
    }
}

#endif // TS_NET_IMPLEMENTATION