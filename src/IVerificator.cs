namespace JwtVerificator
{
    public interface IVerificator
    {
        bool SimpleECDsaValidation(string token);
        bool SimpleRSAValidation(string token);
    }
}