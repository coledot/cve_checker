#! /usr/bin/env ruby

require 'nokogiri'
require 'open-uri'
require 'yaml'
require 'mail'

cve_base_uri = 'https://www.cvedetails.com'

gmail_address = 'cole.thompson@gmail.com'
secrets = YAML.load_file "secrets.yml"
gmail_password = secrets['gmail_password']

cve_products = [
  {
    name: "OpenSSL",
    search_uri: 'https://www.cvedetails.com/vulnerability-list/vendor_id-217/product_id-383/Openssl-Openssl.html'
  },
  {
    name: "OpenVPN",
    search_uri: 'https://www.cvedetails.com/vulnerability-list/vendor_id-3278/product_id-5768/Openvpn-Openvpn.html'
  },
  {
    name: "OpenSSH",
    search_uri: 'https://www.cvedetails.com/vulnerability-list/vendor_id-97/product_id-585/Openbsd-Openssh.html'
  },
]

# FIXME gracefully handle a missing file and/or missing products
latest_cve_info = YAML.load_file "latest_cve.yml"

new_product_cves = {}

cve_products.each do |product|
  # do search
  search_page = Nokogiri::HTML(open(product[:search_uri]))
  cve_search_results = search_page.css('.searchresults tr.srrowns')

  if cve_search_results.length > 0
    latest_cve_result = cve_search_results[0]
    # do we have new cves?
    if latest_cve_result.css('td')[1].text != latest_cve_info[product[:name]][:cve_id]
      new_product_cves[product[:name]] = []

      cve_search_results.each do |cve_result|
        cve_id = cve_result.css('td')[1].text
        cve_href = cve_result.css('td a')[1]['href']

        if cve_id == latest_cve_info[product[:name]][:cve_id]
          break
        end

        new_product_cves[product[:name]] << { cve_id: cve_id, cve_url: cve_base_uri + cve_href }
      end
    end

   latest_cve_info[product[:name]][:cve_id] = latest_cve_result.css('td')[1].text
   latest_cve_info[product[:name]][:last_time_run] = Time.now.utc
  end
end

# build message
message = ""
new_product_cves.each do |product_cve|
  if product_cve[1].length == 0
    next
  end

  message += "New CVEs for #{product_cve[0]}:\n"
  product_cve[1].each do |cve|
    message += "#{cve[:cve_id]} #{cve[:cve_url]}\n"
  end
  message += "\n"
end

if message != ""
  # send email
  smtp_options = { :address              => "smtp.gmail.com",
                   :port                 => 587,
                   :user_name            => gmail_address,
                   :password             => gmail_password,
                   :authentication       => 'plain',
                   :enable_starttls_auto => true  }
  Mail.defaults do
    delivery_method :smtp, smtp_options
  end
  Mail.deliver do
    to      "cole.thompson@gmail.com"
    from    "cole.thompson@gmail.com"
    subject "New CVEs found"
    body    message
  end
end

File.open("latest_cve.yml", "w") { |file| file.write YAML.dump latest_cve_info }
