import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Observable } from 'rxjs';
import { JwtPayload } from '../interfaces/jwt-payload';
import { AuthService } from '../auth.service';

@Injectable()
export class AuthGuard implements CanActivate {

  constructor(
    private jwtService:JwtService,
    private authService:AuthService
  ) {}

  async canActivate(context: ExecutionContext,): Promise<boolean> {

    const req = context.switchToHttp().getRequest();
    const token = this.extractTokenFromHeader(req);
    
   try{ if(!token) {
      throw new UnauthorizedException('Token not found');
    }

    const payload = await this.jwtService.verifyAsync<JwtPayload>(
      token, { secret: process.env.JWT_SEED }
    );

    const user = await this.authService.findUserById(payload.id);
    if(!user) throw new UnauthorizedException('User does not exists');
    if (!user.isActive) throw new UnauthorizedException('User is inactive');

    req['user'] = user;
  
  } catch (error) {
      throw new UnauthorizedException('Token not valid');
    }


    return true;
  }

  private extractTokenFromHeader(request: Request): string | undefined {
    const [type, token] = request.headers['authorization']?.split(' ') ?? [];
    return type === 'Bearer' ? token : undefined;
  }
}
