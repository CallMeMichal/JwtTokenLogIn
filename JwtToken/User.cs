namespace JwtToken
{
    public partial class User
    {
        public int Id { get; set; }
        public string Name { get; set; } = null!;
        public string Email { get; set; } = null!;
        public string Pass { get; set; } = null!;
        public int? RoleId { get; set; }

        public virtual Role? Role { get; set; }
    }
}