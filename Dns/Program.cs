using System;
using System.Globalization;
using System.Threading;
using System.Threading.Tasks;
using DnsClient;
using DnsClient.Protocol;
using Whois.NET;

class Program
{
    static async Task Main(string[] args)
    {
        string domainName;


        do
        {
            Console.Write("Lütfen kontrol etmek istediğiniz alan adını veya alt alan adını girin (çıkmak için 'exit' yazın): ");
            domainName = Console.ReadLine();


            if (!string.IsNullOrEmpty(domainName) && domainName.ToLower() != "exit")
            {
                // Alan adı formatını kontrol et
                if (!domainName.Contains("."))
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("Eksik alan adı uzantısı (örneğin, .com) girdiniz. Lütfen tam alan adı giriniz.");
                    Console.ResetColor();
                    continue;
                }

                // Kum saati animasyonu başlat
                var cancellationTokenSource = new CancellationTokenSource();
                Task.Run(() => ShowLoadingAnimation(cancellationTokenSource.Token));

                if (IsSubdomain(domainName))
                {
                    // Alt alan adı için DNS sorgusu
                    await CheckDnsRecords(domainName);
                }
                else
                {
                    // Alan adı bitiş süresi sorgusu başlatılıyor
                    var whoisTask = CheckDomainDetails(domainName);
                    var timeoutTask = Task.Delay(TimeSpan.FromMinutes(1));

                    if (await Task.WhenAny(whoisTask, timeoutTask) == timeoutTask)
                    {
                        // 1 dakika geçti, bilgilendirme mesajı göster
                        Console.ForegroundColor = ConsoleColor.Yellow;
                        Console.WriteLine("Alan adı bitiş süresi sorgulanıyor, lütfen bekleyin...");
                        Console.ResetColor();

                        // Asıl sorgu işlemi bitene kadar devam etmesini bekliyoruz
                        await whoisTask;
                    }
                }

                // Kum saati animasyonunu durdur
                cancellationTokenSource.Cancel();
            }
            else if (string.IsNullOrEmpty(domainName))
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("Geçerli bir alan adı girmediniz.");
                Console.ResetColor();
            }

        } while (domainName.ToLower() != "exit");

        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine("Programdan çıkılıyor...");
        Console.ResetColor();
    }

    static async Task CheckDomainDetails(string domainName)
    {
        try
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("\n--- DNS SOA Kayıtları ---");
            Console.ResetColor();

            // DNS SOA kaydı sorgusu
            var lookup = new LookupClient();
            var result = await lookup.QueryAsync(domainName, QueryType.SOA);

            foreach (var record in result.AllRecords)
            {
                if (record is SoaRecord soaRecord)
                {
                    Console.WriteLine($"Domain: {domainName}");
                    Console.WriteLine($"Primary Name Server: {soaRecord.MName}");
                    Console.WriteLine($"Responsible Email: {soaRecord.RName}");
                    Console.WriteLine($"Serial Number: {soaRecord.Serial}");
                    Console.WriteLine($"Refresh Rate: {soaRecord.Refresh}");
                    Console.WriteLine($"Retry Rate: {soaRecord.Retry}");
                    Console.WriteLine($"Expire Rate: {soaRecord.Expire}");
                    Console.WriteLine($"Minimum TTL: {soaRecord.Minimum}");
                }
            }

            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("\n--- Alan Adı Bitiş Tarihi ---");
            Console.ResetColor();

            // WHOIS sorgusunu birkaç kez deneme mekanizması
            bool success = false;

            while (!success)
            {
                try
                {
                    var whoisResponse = WhoisClient.Query(domainName, "whois.verisign-grs.com"); // Alternatif WHOIS sunucusu kullan

                    string rawResponse = whoisResponse.Raw;

                    string expiryDateString = null;
                    var lines = rawResponse.Split(new[] { "\r\n", "\r", "\n" }, StringSplitOptions.None);

                    foreach (var line in lines)
                    {
                        if (line.Contains("Expiry Date") || line.Contains("Expiration Date") || line.Contains("Registry Expiry Date"))
                        {
                            expiryDateString = line.Split(':')[1].Trim();
                            break;
                        }
                    }

                    if (!string.IsNullOrEmpty(expiryDateString))
                    {
                        DateTime expiryDate;
                        if (DateTime.TryParse(expiryDateString, out expiryDate))
                        {
                            Console.ForegroundColor = ConsoleColor.Green;
                            Console.WriteLine($"Tarih normal olarak ayrıştırıldı: {expiryDate}");
                        }
                        else
                        {
                            expiryDate = DateTime.ParseExact(expiryDateString, "yyyy-MM-ddTHH", CultureInfo.InvariantCulture);
                            Console.ForegroundColor = ConsoleColor.Green;
                            Console.WriteLine($"Tarih elle ayrıştırıldı: {expiryDate}");
                        }

                        DateTime currentDate = DateTime.Now;

                        if (expiryDate < currentDate)
                        {
                            Console.ForegroundColor = ConsoleColor.Red;
                            Console.WriteLine($"{domainName} süresi dolmuş. ({expiryDate})");
                        }
                        else
                        {
                            Console.ForegroundColor = ConsoleColor.Green;
                            Console.WriteLine($"{domainName} süresi dolmamış. Bitiş tarihi: {expiryDate}");
                        }
                    }
                    else
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine($"{domainName} için bitiş tarihi bilgisi bulunamadı.");
                    }

                    success = true;
                }
                catch (Exception ex)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"\nAlan adı bilgisi alınırken bir hata oluştu: {ex.Message}");
                    success = true; // Hata durumunda döngüden çık
                }
            }
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"\nAlan adı bilgisi alınırken bir hata oluştu: {ex.Message}");
            Console.ResetColor();
        }
    }

    static async Task CheckDnsRecords(string subdomain)
    {
        try
        {
            var lookup = new LookupClient();
            var result = await lookup.QueryAsync(subdomain, QueryType.ANY);

            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"\n--- {subdomain} için DNS Kayıtları ---");
            Console.ResetColor();

            foreach (var record in result.AllRecords)
            {
                Console.WriteLine(record.ToString());
            }

            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("DNS kayıtları başarıyla alındı.");
            Console.ResetColor();
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"\nDNS kayıtları alınırken bir hata oluştu: {ex.Message}");
            Console.ResetColor();
        }
    }

    static bool IsSubdomain(string domain)
    {
        return domain.Split('.').Length > 2;
    }

    static void ShowLoadingAnimation(CancellationToken token)
    {
        char[] animationChars = new[] { '|', '/', '-', '\\' };
        int animationIndex = 0;

        while (!token.IsCancellationRequested)
        {
            Console.Write($"\rLütfen bekleyin... {animationChars[animationIndex++ % animationChars.Length]}");
            Thread.Sleep(100);
        }

        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine("\rİşlem tamamlandı!               ");
        Console.ResetColor();
    }
}
