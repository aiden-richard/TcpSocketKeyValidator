using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using TcpSocketKeyValidator.Crypto;

namespace TcpSocketKeyValidator.Networking;

internal class TcpPeer : IDisposable
{
    private RSA rsa = RSA.Create();
    private byte[] PublicKey;
    private byte[]? PeerPublicKey;

    private Socket? connection;
    private bool IsHost;

    public TcpPeer()
    {
        PublicKey = rsa.ExportRSAPublicKey();
    }

    public async Task SendMessage(byte[] message)
    {
        if (connection == null)
        {
            throw new InvalidOperationException("No connection established");
        }

        byte[] lengthBytes = BitConverter.GetBytes(message.Length);
        await connection.SendAsync(new ArraySegment<byte>(lengthBytes), SocketFlags.None);
        await connection.SendAsync(new ArraySegment<byte>(message), SocketFlags.None);
    }

    public async Task<byte[]> ReceiveMessage()
    {
        if (connection == null)
        {
            throw new InvalidOperationException("No connection established");
        }

        byte[] lengthBytes = await ReadExact(4);
        int messageLength = BitConverter.ToInt32(lengthBytes, 0);

        return await ReadExact(messageLength);
    }

    private async Task<byte[]> ReadExact(int numBytes)
    {
        if (connection == null)
        {
            throw new InvalidOperationException("No connection established");
        }

        byte[] buffer = new byte[numBytes];
        int bytesRead = 0;

        while (bytesRead < numBytes)
        {
            int received = await connection.ReceiveAsync(new ArraySegment<byte>(buffer, bytesRead, numBytes - bytesRead), SocketFlags.None);
            if (received == 0)
            {
                throw new SocketException((int)SocketError.ConnectionReset);
            }
            bytesRead += received;
        }

        return buffer;
    }

    public async Task<bool> TryConnect(string host, int port)
    {
        try
        {
            IsHost = false;
            IPEndPoint EndPoint = new (IPAddress.Parse(host), port);
            connection = new Socket(EndPoint.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            
            await connection.ConnectAsync(EndPoint);
            Console.WriteLine($"Connected to peer at {EndPoint}");

            return true;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Failed to connect: {ex.Message}");
            return false;
        }
    }

    public async Task<bool> TryAcceptConnection(int port)
    {
        try
        {
            IsHost = true;
            IPEndPoint EndPoint = new (IPAddress.Any, port);
            Socket listener = new (EndPoint.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            
            listener.Bind(EndPoint);
            listener.Listen(1);
            
            Console.WriteLine($"Waiting for connection on port {port}...");
            connection = await listener.AcceptAsync();
            Console.WriteLine($"Peer connected from {connection.RemoteEndPoint}");
            
            listener.Close();
            listener.Dispose();

            return true;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Failed to accept connection: {ex.Message}");
            return false;
        }
    }

    public async Task<bool> ExchangeKeys()
    {
        try
        {
            Task sendTask = SendPublicKey();
            Task receiveTask = ReceivePublicKey();

            await Task.WhenAll(sendTask, receiveTask);

            return true;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error during key exchange: {ex.Message}");
            return false;
        }
    }

    private async Task SendPublicKey()
    {
        await SendMessage(PublicKey);
        Console.WriteLine("Public key sent to peer.");
    }

    private async Task ReceivePublicKey()
    {
        PeerPublicKey = await ReceiveMessage();
        Console.WriteLine("Public key received from peer:");
        Console.WriteLine(Convert.ToBase64String(PeerPublicKey) + "\n");
    }

    public async Task<bool> ValidateConnection()
    {
        try
        {
            if (PeerPublicKey == null)
            {
                throw new InvalidOperationException("Peer public key not received");
            }
            
            bool isValid;
            
            if (IsHost)
            {
                // Host validates peer first, then responds to peer's challenge
                isValid = await SendChallenge();
                if (isValid)
                {
                    isValid = await RespondToChallenge();
                }
            }
            else
            {
                // Client responds to host's challenge first, then validates host
                isValid = await RespondToChallenge();
                if (isValid)
                {
                    isValid = await SendChallenge();
                }
            }

            return isValid;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Peer public key validation failed: {ex.Message}");
            return false;
        }
    }

    private async Task<bool> SendChallenge()
    {
        try
        {
            byte[] challenge = new byte[32];
            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(challenge);
            }

            await SendMessage(challenge);
            Console.WriteLine("Challenge sent to peer.");

            byte[] signature = await ReceiveMessage();
            
            bool isValid = Helpers.VerifySignature(challenge, signature, PeerPublicKey);

            if (isValid)
            {
                Console.WriteLine("Peer's signature is valid.");
            }
            else
            {
                Console.WriteLine("Peer's signature is invalid.");
            }

            return isValid;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Key validation failed: {ex.Message}");
            return false;
        }
    }

    private async Task<bool> RespondToChallenge()
    {
        try
        {
            byte[] challenge = await ReceiveMessage();
            Console.WriteLine("Challenge received from peer.");

            byte[] signature = rsa.SignData(challenge, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            await SendMessage(signature);
            Console.WriteLine("Signature sent in response to challenge.");

            return true;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error responding to challenge: {ex.Message}");
            return false;
        }
    }

    public void Dispose()
    {
        connection?.Close();
        connection?.Dispose();
        rsa.Dispose();
        GC.SuppressFinalize(this);
    }
}