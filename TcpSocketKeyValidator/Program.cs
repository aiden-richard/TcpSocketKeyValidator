using TcpSocketKeyValidator.Networking;

namespace TcpSocketKeyValidator;

class Program
{
    static async Task Main()
    {
        bool ishost;
        do
        {
            Console.Write("Enter either 'client' or 'server': ");
            string? input = Console.ReadLine();

            if (input == "client" || input == "server")
            {
                ishost = input == "server";
                break;
            }
            else
            {
                Console.WriteLine("Invalid input. Please enter 'client' or 'server'.");
                ishost = false;
            }
        }
        while (true);

        int port = 12345;
        string host = "127.0.0.1";

        if (ishost)
        {
            TcpPeer server = new TcpPeer();

            await server.TryAcceptConnection(port);
            await server.ExchangeKeys();
        }
        else
        {
            TcpPeer client = new TcpPeer();

            await client.TryConnect(host, port);
            await client.ExchangeKeys();
        }
    }
}