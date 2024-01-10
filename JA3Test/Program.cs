using HttpTwo;
using JA3;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Text;

namespace JA3Test
{
    internal class Program
    {
        static void Main(string[] args)
        {
            //var l = new TcpListener(6735);
            //l.Start();
            //while (true)
            //{
            //    var s=l.AcceptSocket();
            //    var buff=new byte[1024*4];
            //    var count=s.Receive(buff);
            //    var str=Encoding.UTF8.GetString(buff,0,count);
            //    var resp = "";
            //    s.Send(Encoding.ASCII.GetBytes("HTTP/1.1 200 Connection Established\r\n\r\n"));
            //    count = s.Receive(buff);
            //    var str2 = Encoding.UTF8.GetString(buff, 0, count);
            //}

            var url_ja3 = "https://tls.browserleaks.com/json";

            var handler = new Ja3MessageHandler();
            handler.proxy = new System.Net.WebProxy("127.0.0.1", 10809);
            using (var client = new HttpClient(handler))
            {
                client.DefaultRequestHeaders.Add("Tenant-Identifier", "cQuYv9mLXHbhDLgXzZmPRspmm4gz6TmrF8kaZ9uLsZCJTLvvKhuLMfRdBCvM9pbt");
                client.DefaultRequestHeaders.Add("Origin", "https://www.baidu.com");
                client.DefaultRequestHeaders.Add("Referer", "https://www.baidu.com/");
                client.DefaultRequestHeaders.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36");
                client.DefaultRequestHeaders.Add("accept", "*/*");
                client.DefaultRequestHeaders.Add("accept-encoding", "gzip, deflate, br");
                var content = new StringContent("{\"passengers\":[{\"code\":\"ADT\",\"count\":3},{\"code\":\"CHD\",\"count\":0},{\"code\":\"INF\",\"count\":0}],\"routes\":[{\"fromAirport\":\"YVR\",\"toAirport\":\"MCO\",\"departureDate\":\"2024-02-03\",\"startDate\":\"2024-01-31\",\"endDate\":\"2024-02-06\"}],\"currency\":\"CAD\",\"fareTypeCategories\":null,\"isManageBooking\":false,\"languageCode\":\"en-us\"}",Encoding.UTF8, "application/json");
                //var str3 = client.PostAsync("https://api-production-lynxair-booksecure.ezyflight.se/api/v1/Availability/SearchShop", content).Result.Content.ReadAsStringAsync().Result;
                //var str = client.GetStringAsync("https://www.nokair.com/ManageBooking/Login").Result;
                var str2 = client.GetStringAsync(url_ja3).Result;
                Console.WriteLine(str2);
            }
            Console.WriteLine("--".PadRight(30));
            //using (var client = new HttpClient())
            //{
            //    var str2 = client.GetStringAsync(url_ja3).Result;
            //    Console.WriteLine(str2);
            //}
            var handler2 = new Http2MessageHandler()
            {
                Proxy = new System.Net.WebProxy("127.0.0.1", 10809)
            };
            using (var client = new HttpClient(handler2))
            {
                var str2 = client.GetStringAsync(url_ja3).Result;
                Console.WriteLine(str2);
            }

            var client2 = new HttpClient();
            var proxy = client2.GetStringAsync("https://spider.xxklf.com/proxy/api/proxy/get?name=5J").Result;
            proxy = "127.0.0.1:10809";
            //proxy = "proxy.smartproxycn.com:1000@dotnet:776741463R";
            var tmp1 = proxy.Split('@');
            var tmp = tmp1[0].Split(':');
            var p = new System.Net.WebProxy(tmp[0], Convert.ToInt32(tmp[1])); ;
            if (tmp1.Length == 2)
            {
                var tmp2 = tmp1[1].Split(':');
                p.Credentials=new NetworkCredential(tmp2[0], tmp2[1]);
            }
            handler.proxy = p;

            using (var client = new HttpClient(handler))
            {
                client.DefaultRequestHeaders.Add("Authorization", "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJjb21wYW55IjoiQ0VCVSBBaXIgSW5jLiIsIm5hbWUiOiJvbW5pWCIsInZlcnNpb24iOjEsImNvZGVWZXJzaW9uIjoiUHRFRHNWNVA1QUhMb0FoWnk3eHE1SW5XbGZOTW9WaDkifQ.rJdOfwQPOLGObQUkZOX0eEfpXmqHtAkeXNLjorQvQj4");
                client.DefaultRequestHeaders.Add("Content", "U2FsdGVkX19TEcKUU7LIADxIjGXDY63hAKvU79CHGwc=");
                client.DefaultRequestHeaders.Add("Uniqueid", "f2f9f913-8353-4a44-9979-e5c65a0197f7");
                client.DefaultRequestHeaders.Add("Referer", "https://www.cebupacificair.com/");
                client.DefaultRequestHeaders.Add("Origin", "https://www.cebupacificair.com");
                //client.DefaultRequestHeaders.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0");
                client.DefaultRequestHeaders.Add("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36");
                client.DefaultRequestHeaders.Add("accept", "*/*");
                client.DefaultRequestHeaders.Add("accept-encoding", "gzip, deflate, br");
               
                //client.DefaultRequestVersion = new Version(2, 0);
                //client.DefaultVersionPolicy = HttpVersionPolicy.RequestVersionOrHigher;
                var http_content = new ByteArrayContent(new byte[0]);
                http_content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/json");
                //var s1 = client.GetStringAsync(url_ja3).Result;
                using var resp = client.PostAsync("https://soar.cebupacificair.com/ceb-omnix_proxy", http_content).Result;
                var r = resp.Content.ReadAsStringAsync().Result;
            }
            Console.WriteLine("Hello, World!");
        }
    }
}
