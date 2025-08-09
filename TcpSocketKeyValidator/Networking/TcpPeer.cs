using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;

namespace TcpSocketKeyValidator.Networking;

internal class TcpPeer : IDisposable
{
    private RSA rsa = RSA.Create();
    private byte[] PrivateKey;
    private byte[] PublicKey;

    private Socket? connection;
    private bool IsHost;

    public TcpPeer()
    {
        PrivateKey = rsa.ExportRSAPrivateKey();
        PublicKey = rsa.ExportRSAPublicKey();
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
            if (connection == null)
            {
                throw new InvalidOperationException("No connection established");
            }

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
        await connection.SendAsync(new ArraySegment<byte>(PublicKey), SocketFlags.None);
        Console.WriteLine("Public key sent to peer.");
    }

    private async Task ReceivePublicKey()
    {
        byte[] buffer = new byte[1024];
        int received = await connection.ReceiveAsync(new ArraySegment<byte>(buffer), SocketFlags.None);
        byte[] receivedKey = new byte[received];
        Array.Copy(buffer, receivedKey, received);
        Console.WriteLine("Public key received from peer.");
        Console.WriteLine(Convert.ToBase64String(receivedKey) + "\n");
    }

    public void Dispose()
    {
        connection?.Close();
        connection?.Dispose();
        rsa.Dispose();
        GC.SuppressFinalize(this);
    }
}