# encoding: utf-8
require "logstash/util/buftok"
require "logstash/util/charset"
require "logstash/codecs/base"

# produce an event with the payload as the 'message' field and a '_parsefailure' tag.
class LogStash::Codecs::Fortinet < LogStash::Codecs::Base
  config_name "fortinet"

  # Indicate the delimiter your input puts each CEF event.
  config :delimiter, :validate => :string

  # Cache of a gsub pattern that matches a backslash-escaped backslash or backslash-escaped equals, _capturing_ the escaped character
  EXTENSION_VALUE_ESCAPE_CAPTURE = /\\([\\=])/

  # Serve per individuare le key nel messaggio
  EXTENSION_KEY_PATTERN = /(?:\w+(?:\.[^\s]\w+[^\|\s\.\=\\]+)?(?==))/
  # Serve per individuare i value della sezione Extension
  EXTENSION_VALUE_PATTERN = /(?:\S|\s++(?!#{EXTENSION_KEY_PATTERN}=))*/
  # Metto insieme per ottenere l'espressione che mi permette di individuare le coppie key/value
  EXTENSION_KEY_VALUE_SCANNER = /(#{EXTENSION_KEY_PATTERN})=(#{EXTENSION_VALUE_PATTERN})\s*/

  public
  def initialize(params={})
    super(params)

    # Input deve essere codificato in UTF-8
    @utf8_charset = LogStash::Util::Charset.new('UTF-8')
    @utf8_charset.logger = self.logger

    # Se @delimiter è indicato tra i parametri... 
    if @delimiter
      @delimiter = @delimiter.gsub("\\r", "\r").gsub("\\n", "\n")
      # ... @delimiter viene usato come elemento per la separazione delle linee		
      @buffer = FileWatch::BufferedTokenizer.new(@delimiter)
      # Nota: BufferedTokenizers permette di usare @delimeter in String#split per separare i dati in input
      end
  end
   
  # In questa sezione effettuiamo il parsing
  public
  def decode(data, &block)
  # Se è indicato @delimeter allora si sta passando un blocco di log, quindi vanno separati  
    if @delimiter
      @buffer.extract(data).each do |line|
	# Passiamo le diverse linee di log al parser        
	handle(line, &block)
      end
    else
      # Se è un solo log, lo passiamo direttamente al parser
      handle(data, &block)
    end
  end

  # Definiamo il parser vero e proprio
  def handle(data, &block)
    # Creiamo l'evento
    event = LogStash::Event.new

    # Usiamo per il log la codifica UTF-8
    @utf8_charset.convert(data)
    # Se l'encoding non ha avuto successo non andiamo avanti nel parsing, perchè nascerebbero errori
    fail('invalid byte sequence in UTF-8') unless data.valid_encoding?

    # Nel caso ci siano caratteri a delimitare l'inizio e alla fine del log, vengono rimossi
    if data[0] == "\""
      data = data[1..-2]
    end
    
    # Il log da parsare viene inserito in una variabile dal nome message
    message = data

    # Se la variabile messaggio è impostato e contiene degli uguali
    if message && message.include?('=')
      # Leviamo dal messaggio eventuali caratteri di spazio alla fine e all'inizio
      message = message.strip
      # Scopo di questo ciclo è ricavare le diverse coppie key/value del messaggio
      message.scan(EXTENSION_KEY_VALUE_SCANNER) do |extension_field_key, raw_extension_field_value|
        # Con il seguente comando evitiamo che campi con sintassi simile a quella di un array possano creare errori
        extension_field_key = extension_field_key.sub(EXTENSION_KEY_ARRAY_CAPTURE, '[\1]\2') if extension_field_key.end_with?(']')
        # Controlliamo la presenze di sequenze di escape e di simboli ", poi rimuoviamo per evitare problemi in output
	extension_field_value = raw_extension_field_value.gsub(EXTENSION_VALUE_ESCAPE_CAPTURE, '\1').gsub(/["]/,'')
	
	# A questo punto nell'evento settiamo la coppia key-value trovata
      event.set(extension_field_key, extension_field_value)
      end
    end

    # Portiamo in uscita l'evento
    yield event

    # In caso di errore viene mostrato il seguente messaggio
  rescue => e
    @logger.error("Failed to decode Fortinet payload. Generating failure event with payload in message field.", :error => e.message, :backtrace => e.backtrace, :data => data)
    yield LogStash::Event.new("message" => data, "tags" => ["_Fortinetparsefailure"])
  end
end